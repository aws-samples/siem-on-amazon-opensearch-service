#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import configparser
import copy
import json
import importlib
import sys
import os
import re
import boto3
import botocore
from elasticsearch import Elasticsearch, RequestsHttpConnection
from requests_aws4auth import AWS4Auth
import siem

__version__ = '2.1.0-beta3'
print('version: ' + __version__)


def get_es_hostname():
    # get ES_ENDPOINT
    if 'ES_ENDPOINT' in os.environ:
        es_hostname = os.environ.get('ES_ENDPOINT', '')
    else:
        # For local shell execution
        aes_config = configparser.ConfigParser(
            interpolation=configparser.ExtendedInterpolation())
        aes_config.read('aes.ini')
        aes_config.sections()
        if 'aes' in aes_config:
            es_hostname = aes_config['aes']['es_endpoint']
        else:
            print('ERROR[{0}]: You need to set ES_ENDPOINT in ENVRIONMENT '
                  'or modify aes.ini. exit'.format(os.getpid(),))
            raise Exception('No ES_ENDPOINT in Environemnt')
    return es_hostname


def initialize_es_connection(es_hostname):
    es_region = es_hostname.split('.')[1]
    # For Debug
    # boto3.set_stream_logger('botocore', level='DEBUG')
    credentials = boto3.Session().get_credentials()
    service = 'es'
    awsauth = AWS4Auth(
        credentials.access_key, credentials.secret_key, es_region, service,
        session_token=credentials.token)
    es_conn = Elasticsearch(
        hosts=[{'host': es_hostname, 'port': 443}], http_auth=awsauth,
        use_ssl=True, http_compress=True, verify_certs=True,
        retry_on_timeout=True, connection_class=RequestsHttpConnection,
        timeout=60)
    return es_conn


def load_user_custom_libs():
    # /opt is mounted by lambda layer
    print('These files are in /opt: ' + str(os.listdir(path='/opt/')))
    user_libs = []
    if os.path.isdir('/opt/siem'):
        print('These files are in /opt/siem: '
              + str(os.listdir(path='/opt/siem')))
        user_libs = [i for i in os.listdir('/opt/siem/') if 'sf_' in i]
        sys.path.append('/opt/siem')
    return user_libs


def timestr_to_hours(timestr):
    try:
        hours, minutes = timestr.split(':')
        hours = int(hours) + int(minutes) / 60
    except ValueError:
        hours = timestr
    except Exception:
        raise Exception(timestr)
    return str(hours)


def get_etl_config():
    etl_config = configparser.ConfigParser(
        interpolation=configparser.ExtendedInterpolation())
    etl_config.read('aws.ini')
    # overwride with user configration
    etl_config.read('/opt/user.ini')
    etl_config.read('user.ini')
    etl_config.sections()
    if 'doc_id' not in etl_config['DEFAULT']:
        raise Exception('ERROR[{0}]: invalid config file: aws.ini. exit'
                        ''.format(os.getpid(),))
    for each_config in etl_config:
        etl_config[each_config]['index_tz'] = timestr_to_hours(
            etl_config[each_config]['index_tz'])
        etl_config[each_config]['timestamp_tz'] = timestr_to_hours(
            etl_config[each_config]['timestamp_tz'])
    return etl_config


def load_modules_on_memory(etl_config, user_libs):
    for logtype in etl_config:
        if etl_config[logtype].get('script_ecs'):
            mod_name = 'sf_' + logtype.replace('-', '_')
            # old_mod_name is for compatibility
            old_mod_name = 'sf_' + logtype
            if mod_name + '.py' in user_libs:
                importlib.import_module(mod_name)
            elif old_mod_name + '.py' in user_libs:
                importlib.import_module(mod_name)
            else:
                importlib.import_module('siem.' + mod_name)


def make_not_loading_list(etl_config):
    # ignore list of not loading to es
    not_loading_list = {}
    if etl_config['DEFAULT'].getboolean('ignore_own_logs'):
        user_agent = etl_config['DEFAULT'].get('custom_user_agent', '')
        if user_agent:
            not_loading_list['cloudtrail'] = {'userAgent': user_agent}
            not_loading_list['s3accesslog'] = {'UserAgent': user_agent}
    return not_loading_list


def make_s3_session_config(etl_config):
    user_agent = etl_config['DEFAULT'].get('custom_user_agent', '')
    user_agent_ver = etl_config['DEFAULT'].get('custom_user_agent_ver', '')
    if user_agent:
        s3_session_config = botocore.config.Config(
            user_agent=f'{user_agent}/{user_agent_ver}')
    else:
        s3_session_config = None
    return s3_session_config


def get_es_entry(logfile, logconfig, not_loading_list):
    """get elasticsearch entry
    To return json to load AmazonES, extract log, map fields to ecs fields and
    enriich ip addresses with geoip. Most important process.
    """
    # load config object on memory to avoid disk I/O accessing
    copy_attr_list = (
        'logtype', 'msgformat', 'file_format', 'header', 's3bucket', 's3key',
        'accountid', 'region', 'loggroup', 'logstream', 'via_firelens')
    logs = {}
    for key in copy_attr_list:
        logs[key] = copy.copy(getattr(logfile, key))

    # load regex pattern for text log on memory
    log_pattern_prog = None
    if 'log_pattern' in logconfig:
        log_pattern_prog = re.compile(logconfig['log_pattern'])

    # load custom script
    if logconfig['script_ecs']:
        mod_name = 'sf_' + logs['logtype'].replace('-', '_')
        # old_mod_name is for compatibility
        old_mod_name = 'sf_' + logs['logtype']
        if mod_name + '.py' in user_libs:
            sf_module = importlib.import_module(mod_name)
        elif old_mod_name + '.py' in user_libs:
            sf_module = importlib.import_module(old_mod_name)
        else:
            sf_module = importlib.import_module('siem.' + mod_name)
    else:
        sf_module = None

    for logdata in logfile.logdata_list:
        # インスタンスを作ってログタイプを入れる
        logparser = siem.LogParser(
            logdata=logdata, logtype=logs['logtype'],
            msgformat=logs['msgformat'], logformat=logs['file_format'],
            header=logs['header'], logconfig=logconfig,
            s3bucket=logs['s3bucket'], s3key=logs['s3key'],
            accountid=logs['accountid'], region=logs['region'],
            loggroup=logs['loggroup'], logstream=logs['logstream'],
            via_firelens=logs['via_firelens'],
            log_pattern_prog=log_pattern_prog, sf_module=sf_module,)
        # 自分自身のログを無視する。ESにはロードしない。
        is_ignored = logparser.check_ignored_log(not_loading_list)
        if is_ignored or logparser.is_ignored:
            continue
        # idなどの共通的なフィールドを追加する
        logparser.add_basic_field()
        # print('DEBUG: ID: {0}'.format(logparser.id))
        # 同じフィールド名で複数タイプがあるとESにロードするときにエラーになるので
        # 該当フィールドだけテキスト化する
        logparser.clean_multi_type_field()
        # フィールドをECSにマッピングして正規化する
        logparser.transform_to_ecs()
        # 一部のフィールドを修正する
        logparser.transform_by_script()
        # ログにgeoipなどの情報をエンリッチ
        logparser.enrich()
        yield {'index': {
            '_index': logparser.indexname, '_id': logparser.index_id}}
        # print(logparser.json)
        yield logparser.json


def check_es_results(results):
    if not results['errors']:
        print('INFO[{0}]: {1} entries were successed to load. It took {2} ms'
              ''.format(os.getpid(), len(results['items']), results['took']))
    else:
        print('ERROR[{0}]: Entries were {1}. But bellow entries were failed '
              'to load'.format(os.getpid(), len(results['items'])))
        error_num = 0
        for result in results['items']:
            if result['index']['status'] >= 300:
                # status code
                # 200:OK, 201:Created, 400:NG
                print('ERROR[{0}]: {1}'.format(os.getpid(), result['index']))
                error_num += 1
        print('ERROR[{0}]: {1} entries were failed to load. It took {2} ms'
              ''.format(os.getpid(), error_num, results['took']))
        raise Exception('{0} of {1} entries were failed to load.'
                        ''.format(error_num, len(results['items'])))


es_hostname = get_es_hostname()
es_conn = initialize_es_connection(es_hostname)
user_libs = load_user_custom_libs()
etl_config = get_etl_config()
load_modules_on_memory(etl_config, user_libs)
not_loading_list = make_not_loading_list(etl_config)
s3_session_config = make_s3_session_config(etl_config)


def lambda_handler(event, context):
    for record in event['Records']:
        if 'body' in record:
            # from sqs-splitted-logs
            record = json.loads(record['body'])
        if 'kinesis' in record:
            logfile = siem.LogKinesis(record, etl_config)
        elif 's3' in record:
            s3 = boto3.client('s3', config=s3_session_config)
            logfile = siem.LogS3(record, etl_config, s3)
        else:
            raise Exception(
                'ERROR[{0}]: invalid input data. exit'.format(os.getpid()))
        if logfile.ignore:
            print('WARN[{0}]: skipped because {1}'.format(
                os.getpid(), logfile.ignore))
            continue
        print('INFO[{0}]: {1}'.format(os.getpid(), logfile.startmsg,))

        # ETL対象のログタイプのConfigだけに限定する
        logconfig = copy.copy(etl_config[logfile.logtype])
        # ESにPUTする
        size = 0
        results = False
        putdata_list = []
        for data in get_es_entry(logfile, logconfig, not_loading_list):
            putdata_list.append(data)
            size += len(str(data))
            # es の http.max_content_length は t2 で10MB なのでデータがたまったらESにロード
            if isinstance(data, str) and size > 6000000:
                results = es_conn.bulk(putdata_list)
                check_es_results(results)
                size = 0
                putdata_list = []
        if size > 0:
            results = es_conn.bulk(putdata_list)
            check_es_results(results)
        elif not results:
            print('INFO[{0}]: No entries were successed to load'.format(
                os.getpid()))


if __name__ == '__main__':
    import argparse
    from datetime import datetime, timezone
    from multiprocessing import Pool
    from functools import partial

    def check_args():
        parser = argparse.ArgumentParser(description='es-loader',)
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument(
            '-b', '--s3bucket', help='s3 bucket where logs are storeed')
        parser.add_argument(
            '-l', '--s3list', help=('s3 object list which you want to load to '
                                    'AmazonES. You can create the list by '
                                    '"aws s3 ls S3BUCKET --recursive"'))
        group.add_argument('-q', '--sqs', help='SQS queue name of DLQ')
        args = parser.parse_args()
        if args.s3bucket:
            if not args.s3list:
                print('You neee to provide s3 object list with -l')
                sys.exit('Exit')
        return args

    def create_event_from_s3list(s3bucket, s3list):
        with open(s3list) as f:
            for num, line_text in enumerate(f.readlines()):
                try:
                    dummy, dummy, dummy, s3key = line_text.split()
                except ValueError:
                    continue
                line_num = num + 1
                s3key = s3key
                event = {'Records': [
                            {'s3': {'bucket': {'name': s3bucket},
                                    'object': {'key': s3key}}}]}
                yield line_num, event, None

    def create_event_from_sqs(queue_name):
        sqs = boto3.resource('sqs')
        queue = sqs.get_queue_by_name(QueueName=queue_name)
        try_list = []
        while True:
            messages = queue.receive_messages(
                MessageAttributeNames=['All'], MaxNumberOfMessages=10,
                VisibilityTimeout=300, WaitTimeSeconds=1)
            if messages:
                for msg in messages:
                    if msg.message_id not in try_list:
                        try_list.append(msg.message_id)
                        event = json.loads(msg.body)
                        if 'Records' in event:
                            # from DLQ
                            pass
                        else:
                            # from aes-siem-sqs-splitted-logs
                            event = {'Records': [json.loads(msg.body)]}
                        yield msg.message_id, event, msg
            else:
                break

    def open_debug_log(outfile):
        error_log = outfile + '.error.log'
        error_debug_log = outfile + '.error_debug.log'
        finish_log = outfile + '.finish.log'
        f_err = open(error_log, 'w')
        f_err_debug = open(error_debug_log, 'w')
        f_finish = open(finish_log, 'w')
        return f_err, f_err_debug, f_finish

    def close_debug_log(outfile, f_err, f_err_debug, f_finish):
        error_log = outfile + '.error.log'
        error_debug_log = outfile + '.error_debug.log'
        f_err.close()
        f_err_debug.close()
        f_finish.close()
        # print number of error
        err_count = sum([1 for _ in open(error_log)])
        if err_count > 0:
            print(f'{err_count} logs are not loaded to ES. See for details, '
                  f'{error_debug_log}')
        else:
            os.remove(error_debug_log)
            os.remove(error_log)

    def my_callback(*args, event=None, context=None, sqsmsg=None,
                    f_finish=None):
        line = context['line']
        s3_bucket = event['Records'][0]['s3']['bucket']['name']
        s3_key = event['Records'][0]['s3']['object']['key']
        f_finish.write(f'{line}\ts3://{s3_bucket}/{s3_key}\n')
        f_finish.flush()
        if sqsmsg:
            sqsmsg.delete()

    def my_err_callback(*args, event=None, context=None, f_err=None,
                        f_err_debug=None):
        line = context['line']
        s3_bucket = event['Records'][0]['s3']['bucket']['name']
        s3_key = event['Records'][0]['s3']['object']['key']
        now = datetime.now(timezone.utc)
        f_err.write(f'{now}\t{line}\t{s3_key}\n')
        f_err.flush()
        f_err_debug.write(f'{line}\ts3://{s3_bucket}/{s3_key}\n')
        f_err_debug.write(f'{args}\n')
        f_err_debug.flush()

    ###########################################################################
    # main logic
    ###########################################################################
    args = check_args()
    if args.s3list:
        outfile = args.s3list
        events = create_event_from_s3list(args.s3bucket, args.s3list)
    elif args.sqs:
        outfile = args.sqs + datetime.now(
            timezone.utc).strftime('-%Y%m%d_%H%M%S')
        events = create_event_from_sqs(args.sqs)
    f_err, f_err_debug, f_finish = open_debug_log(outfile)

    cpu_count = os.cpu_count()
    with Pool(3 * cpu_count) as pool:
        results_pool = []
        for line, event, sqs in events:
            context = {'line': line}
            res = pool.apply_async(
                lambda_handler, (event, context),
                callback=partial(my_callback, event=event, context=context,
                                 f_finish=f_finish, sqsmsg=sqs),
                error_callback=partial(my_err_callback, event=event,
                                       context=context, f_err=f_err,
                                       f_err_debug=f_err_debug))
        pool.close()
        pool.join()

    close_debug_log(outfile, f_err, f_err_debug, f_finish)
    print('INFO: Finishaed batch loading')
