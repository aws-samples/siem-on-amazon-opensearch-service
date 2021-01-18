#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import copy
from functools import wraps
import importlib
import json
import os
import re
import sys
import time

import boto3
from aws_lambda_powertools import Metrics, Logger
from aws_lambda_powertools.metrics import MetricUnit

import siem
from siem import utils, geodb

__version__ = '2.2.0-beta.3'


logger = Logger(stream=sys.stdout, log_record_order=["level", "message"])
logger.info('version: ' + __version__)
metrics = Metrics()

SQS_SPLITTED_LOGS_URL = None
if 'SQS_SPLITTED_LOGS_URL' in os.environ:
    SQS_SPLITTED_LOGS_URL = os.environ['SQS_SPLITTED_LOGS_URL']
ES_HOSTNAME = utils.get_es_hostname()


def extract_logfile_from_s3(record):
    if 'body' in record:
        # from sqs-splitted-logs
        record = json.loads(record['body'])
    if 's3' in record:
        logger.structure_logs(
            append=True, s3_key=record['s3']['object']['key'])
        logfile = siem.LogS3(record, etl_config, s3_client)
    else:
        logger.error('invalid input data. exit')
        raise Exception('invalid input data. exit')
    return logfile


def get_es_entries(logfile, logconfig, exclude_log_patterns):
    """get elasticsearch entries.

    To return json to load AmazonES, extract log, map fields to ecs fields and
    enrich ip addresses with geoip. Most important process.
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
        is_ignored = logparser.check_ignored_log(exclude_log_patterns)
        if is_ignored or logparser.is_ignored:
            continue
        # idなどの共通的なフィールドを追加する
        logparser.add_basic_field()
        # logger.debug({'doc_id': logparser.doc_id})
        # 同じフィールド名で複数タイプがあるとESにロードするときにエラーになるので
        # 該当フィールドだけテキスト化する
        logparser.clean_multi_type_field()
        # フィールドをECSにマッピングして正規化する
        logparser.transform_to_ecs()
        # 一部のフィールドを修正する
        logparser.transform_by_script()
        # ログにgeoipなどの情報をエンリッチ
        logparser.enrich(geodb_instance)
        yield {'index': {
            '_index': logparser.indexname, '_id': logparser.doc_id}}
        # logger.debug(logparser.json)
        yield logparser.json


def check_es_results(results):
    duration = results['took']
    success, error = 0, 0
    error_reasons = []
    if not results['errors']:
        success = len(results['items'])
    else:
        for result in results['items']:
            if result['index']['status'] >= 300:
                # status code
                # 200:OK, 201:Created, 400:NG
                error += 1
                error_reason = result['index'].get('error')
                if error_reason:
                    error_reasons.append(error_reason)

    return duration, success, error, error_reasons


def bulkloads_into_elasticsearch(es_entries, collected_metrics):
    output_size, total_output_size = 0, 0
    total_count, success_count, error_count, es_response_time = 0, 0, 0, 0
    results = False
    putdata_list = []
    error_reason_list = []
    filter_path = ['took', 'errors', 'items.index.status',
                   'items.index.error.reason', 'items.index.error.type']
    for data in es_entries:
        putdata_list.append(data)
        output_size += len(str(data))
        # es の http.max_content_length は t2 で10MB なのでデータがたまったらESにロード
        if isinstance(data, str) and output_size > 6000000:
            total_output_size += output_size
            results = es_conn.bulk(putdata_list, filter_path=filter_path)
            es_took, success, error, error_reasons = check_es_results(results)
            success_count += success
            error_count += error
            es_response_time += es_took
            output_size = 0
            total_count += len(putdata_list)
            putdata_list = []
            error_reason_list.extend([error_reasons])
    if output_size > 0:
        total_output_size += output_size
        results = es_conn.bulk(putdata_list, filter_path=filter_path)
        # logger.debug(results)
        es_took, success, error, error_reasons = check_es_results(results)
        success_count += success
        error_count += error
        es_response_time += es_took
        total_count += len(putdata_list)
        error_reason_list.extend(error_reasons)
    elif not results:
        logger.info('No entries were successed to load')
    collected_metrics['total_output_size'] = total_output_size
    collected_metrics['total_log_load_count'] = total_count
    collected_metrics['success_count'] = success_count
    collected_metrics['error_count'] = error_count
    collected_metrics['es_response_time'] = es_response_time

    return collected_metrics, error_reason_list


def output_metrics(metrics, event=None, logfile=None, collected_metrics={}):
    if not os.environ.get('AWS_EXECUTION_ENV'):
        return
    total_output_size = collected_metrics['total_output_size']
    success_count = collected_metrics['success_count']
    error_count = collected_metrics['error_count']
    es_response_time = collected_metrics['es_response_time']
    input_file_size = event['Records'][0]['s3']['object'].get('size', 0)
    s3_key = event['Records'][0]['s3']['object']['key']
    duration = int(
        (time.perf_counter() - collected_metrics['start_time']) * 1000) + 10
    total_log_count = logfile.total_log_count

    metrics.add_dimension(name="logtype", value=logfile.logtype)
    metrics.add_metric(
        name="InputLogFileSize", unit=MetricUnit.Bytes, value=input_file_size)
    metrics.add_metric(
        name="OutputDataSize", unit=MetricUnit.Bytes, value=total_output_size)
    metrics.add_metric(
        name="SuccessLogLoadCount", unit=MetricUnit.Count, value=success_count)
    metrics.add_metric(
        name="ErrorLogLoadCount", unit=MetricUnit.Count, value=error_count)
    metrics.add_metric(
        name="TotalDurationTime", unit=MetricUnit.Milliseconds, value=duration)
    metrics.add_metric(
        name="EsResponseTime", unit=MetricUnit.Milliseconds,
        value=es_response_time)
    metrics.add_metric(
        name="TotalLogFileCount", unit=MetricUnit.Count, value=1)
    metrics.add_metric(
        name="TotalLogCount", unit=MetricUnit.Count, value=total_log_count)
    metrics.add_metadata(key="s3_key", value=s3_key)


es_conn = utils.initialize_es_connection(ES_HOSTNAME)
user_libs = utils.load_user_custom_libs()
etl_config = utils.get_etl_config()
utils.load_modules_on_memory(etl_config, user_libs)

exclude_own_log_patterns = utils.make_exclude_own_log_patterns(etl_config)
csv_filename = utils.get_exclude_log_patterns_csv_filename(etl_config)
exclude_log_patterns = utils.merge_csv_into_log_patterns(
    exclude_own_log_patterns, csv_filename)
s3_session_config = utils.make_s3_session_config(etl_config)
s3_client = boto3.client('s3', config=s3_session_config)

geodb_instance = geodb.GeoDB()
utils.show_local_dir()


def observability_decorator_switcher(func):
    if os.environ.get('AWS_EXECUTION_ENV'):
        @metrics.log_metrics
        @logger.inject_lambda_context
        @wraps(func)
        def decorator(*args, **kwargs):
            return func(*args, **kwargs)
        return decorator
    else:
        # local environment
        @wraps(func)
        def decorator(*args, **kwargs):
            return func(*args, **kwargs)
        return decorator


@observability_decorator_switcher
def lambda_handler(event, context):
    for record in event['Records']:
        collected_metrics = {'start_time': time.perf_counter()}
        logfile = extract_logfile_from_s3(record)
        if logfile.ignore:
            logger.warn(f'Skipped because {logfile.ignore}')
            continue
        logger.info(logfile.startmsg)

        # ETL対象のログタイプのConfigだけを限定して定義する
        logconfig = etl_config[logfile.logtype]
        # ESにPUTするデータを作成する
        es_entries = get_es_entries(logfile, logconfig, exclude_log_patterns)
        # 作成したデータをESにPUTしてメトリクスを収集する
        collected_metrics, error_reason_list = bulkloads_into_elasticsearch(
            es_entries, collected_metrics)

        output_metrics(metrics, event=event, logfile=logfile,
                       collected_metrics=collected_metrics)
        # raise error to retry if error has occuered
        if collected_metrics['error_count']:
            error_message = (f"{collected_metrics['error_count']}"
                             " of logs were NOT loaded into Amazon ES")
            logger.error(error_message)
            logger.error(error_reason_list[:5])
            raise Exception(error_message)
        else:
            logger.info('All logs were loaded into Amazon ES')


if __name__ == '__main__':
    import argparse
    from datetime import datetime, timezone
    from functools import partial
    from multiprocessing import Pool
    import traceback

    print(__version__)

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
                event = {
                    'Records': [
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
    print('startting main logic on local shell')
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
            try:
                res.get()
            except Exception:
                f_err_debug.write(traceback.format_exc())
                print(traceback.format_exc())

        pool.close()
        pool.join()

    close_debug_log(outfile, f_err, f_err_debug, f_finish)
    print('INFO: Finishaed batch loading')
