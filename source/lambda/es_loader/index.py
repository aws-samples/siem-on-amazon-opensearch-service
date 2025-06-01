#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.10.4'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import json
import logging
import os
import re
import sys
import time
import urllib.parse
import warnings
from functools import lru_cache, wraps

import boto3
from aws_lambda_powertools import Logger, Metrics
from aws_lambda_powertools.metrics import MetricUnit
from opensearchpy import (AuthenticationException, AuthorizationException,
                          RequestError)

import siem
from siem import geodb, ioc, utils, xff

logging.getLogger('opensearch').setLevel(logging.ERROR)
logger = Logger(stream=sys.stdout, log_record_order=["level", "message"])
logger.info(f'version: {__version__}')
logger.info(f'boto3: {boto3.__version__}')
warnings.filterwarnings("ignore", "No metrics to publish*")
metrics = Metrics()

if sys.version_info.major == 3 and sys.version_info.minor < 11:
    msg = f"You are using Python {sys.version}. Please update to Python 3.11"
    logger.error(msg)
    time.sleep(30)
    sys.exit(0)

SQS_SPLITTED_LOGS_URL = None
if 'SQS_SPLITTED_LOGS_URL' in os.environ:
    SQS_SPLITTED_LOGS_URL = os.environ['SQS_SPLITTED_LOGS_URL']
ES_HOSTNAME = utils.get_es_hostname()
SERVICE = ES_HOSTNAME.split('.')[2]
AOSS_TYPE = os.getenv('AOSS_TYPE', '')
docid_set = set()


def extract_logfile_from_s3(record):
    if 's3' in record:
        s3key = record['s3'].get('object', {}).get('key')
        s3bucket = record['s3'].get('bucket', {}).get('name')
    elif 'detail' in record:
        s3key = record['detail'].get('object', {}).get('key')
        s3bucket = record['detail'].get('bucket', {}).get('name')
    else:
        s3key = ''
        s3bucket = ''
    s3key = urllib.parse.unquote_plus(s3key, encoding='utf-8')

    if s3key and s3bucket:
        logger.structure_logs(append=True, s3_key=s3key, s3_bucket=s3bucket)
        logtype = utils.get_logtype_from_s3key(s3key, logtype_s3key_dict)
        logconfig = create_logconfig(logtype)
        client = s3_client

        if s3bucket in control_tower_log_bucket_list:
            if control_tower_s3_client:
                client = control_tower_s3_client
            else:
                logger.warning("es-loader doesn't have valid credential to "
                               "access the S3 bucket in Log Archive")
                raise Exception(f"Failed to download s3://{s3bucket}/{s3key} "
                                "because of invalid credential")
        elif s3bucket.startswith('aws-security-data-lake-'):
            if security_lake_s3_client:
                client = security_lake_s3_client
            else:
                logger.warning("es-loader doesn't have valid credential to "
                               "access the S3 bucket in Security Lake")
                raise Exception(f"Failed to download s3://{s3bucket}/{s3key} "
                                "because of invalid credential")

        logfile = siem.LogS3(record, s3bucket, s3key, logtype, logconfig,
                             client, sqs_queue)
    else:
        logger.warning(
            'Skipped because there is no S3 object. Invalid input data')
        logger.info(record)
        return None

    return logfile


@lru_cache(maxsize=1024)
def get_value_from_etl_config(logtype, key, keytype=None):
    try:
        if keytype is None:
            value = etl_config[logtype][key]
        elif keytype == 'bool':
            value = etl_config[logtype].getboolean(key)
        elif keytype == 'int':
            value = etl_config[logtype].getint(key)
        elif keytype == 're':
            rawdata = etl_config[logtype][key]
            if rawdata:
                value = re.compile(rawdata)
            else:
                value = ''
        elif keytype == 'list':
            temp = etl_config[logtype][key]
            if temp.startswith('['):
                value = [x.strip() for x in temp.strip('[|]').split(',')]
            else:
                value = temp.split()
        elif keytype == 'list_json':
            temp = etl_config[logtype][key]
            if temp:
                value = json.loads(temp)
            else:
                value = []
        else:
            value = ''
    except KeyError:
        logger.exception("Can't find the key in logconfig")
        raise KeyError("Can't find the key in logconfig") from None
    except re.error:
        msg = (f'invalid regex pattern for {key} of {logtype} in '
               'aws.ini/user.ini')
        logger.exception(msg)
        raise Exception(msg) from None
    except json.JSONDecodeError:
        msg = (f'{key} of {logtype} section is invalid list style in '
               'aws.ini/user.ini')
        logger.exception(msg)
        raise Exception(msg) from None
    except Exception:
        logger.exception('unknown error in aws.ini/user.ini')
        raise Exception('unknown error in aws.ini/user.ini') from None
    return value


@lru_cache(maxsize=1024)
def create_logconfig(logtype):
    type_re = ['s3_key_ignored', 'log_pattern', 'multiline_firstline',
               'xml_firstline', 'file_timestamp_format']
    type_int = ['max_log_count', 'text_header_line_number',
                'ignore_header_line_number']
    type_bool = ['via_cwl', 'via_firelens', 'ignore_container_stderr',
                 'timestamp_nano']
    type_list = ['base.tags', 'clientip_xff', 'container.image.tag',
                 'dns.answers',
                 'dns.header_flags', 'dns.resolved_ip', 'dns.type',
                 'ecs', 'static_ecs',
                 'event.category', 'event.type', 'file.attributes',
                 'host.ip', 'host.mac',
                 'ioc_domain', 'ioc_ip',
                 'observer.ip', 'observer.mac',
                 'process.args', 'registry.data.strings',
                 'related.hash', 'related.hosts', 'related.ip', 'related.user',
                 'renamed_newfields',
                 'rule.author', 'threat.tactic.id', 'threat.tactic.name',
                 'threat.tactic.reference', 'threat.technique.id',
                 'threat.technique.name', 'threat.technique.reference',
                 'threat.technique.subtechnique.id',
                 'threat.technique.subtechnique.name',
                 'threat.technique.subtechnique.reference',
                 'tls.client.certificate_chain',
                 'tls.client.supported_ciphers',
                 'tls.server.certificate_chain',
                 'user.roles', 'vulnerability.category',
                 'x509.alternative_names', 'x509.alternative_names',
                 'x509.issuer.country', 'x509.issuer.locality',
                 'x509.issuer.organization', 'x509.issuer.organizational_unit',
                 'x509.issuer.state_or_province', 'x509.subject.common_name',
                 'x509.subject.country', 'x509.subject.locality',
                 'x509.subject.organization',
                 'x509.subject.organizational_unit',
                 'x509.subject.state_or_province']
    type_list_json = ['timestamp_format_list']
    logconfig = {}
    if logtype in ('unknown', 'nodata'):
        return logconfig
    for key in etl_config[logtype]:
        if key in type_re:
            logconfig[key] = get_value_from_etl_config(logtype, key, 're')
        elif key in type_int:
            logconfig[key] = get_value_from_etl_config(logtype, key, 'int')
        elif key in type_bool:
            logconfig[key] = get_value_from_etl_config(logtype, key, 'bool')
        elif key in type_list:
            logconfig[key] = get_value_from_etl_config(logtype, key, 'list')
        elif key in type_list_json:
            logconfig[key] = get_value_from_etl_config(
                logtype, key, 'list_json')
        else:
            logconfig[key] = get_value_from_etl_config(logtype, key)
    if logconfig['file_format'] in ('xml', ):
        logconfig['multiline_firstline'] = logconfig['xml_firstline']
    if SERVICE == 'aoss':
        logconfig['index_rotation'] = 'aoss'
    if logtype in log_exclusion_patterns:
        logconfig['exclusion_patterns'] = log_exclusion_patterns[logtype]
    if logtype in exclusion_conditions:
        logconfig['exclusion_conditions'] = exclusion_conditions[logtype]

    return logconfig


def check_and_create_aliases_if_needed(es_conn):
    auto_rotation_list = []
    aliases_dict = {}
    for logtype in logtype_s3key_dict.keys():
        if get_value_from_etl_config(logtype, 'index_rotation') == 'auto':
            alias = get_value_from_etl_config(logtype, 'index_name')
            auto_rotation_list.append({'logtype': logtype, 'alias': alias})
    if auto_rotation_list:
        logger.info('Creating aliases')
        res = es_conn.cat.aliases(format="json")
        for item in res:
            aliases_dict[item['alias']] = item
        for alias_auto in auto_rotation_list:
            alias = alias_auto['alias']
            if alias not in aliases_dict:
                res = None
                logger.info(f"alias {alias} is being created")
                try:
                    res = es_conn.transport.perform_request(
                        "PUT", f"/{alias}-000001",
                        headers={"Content-Type": "application/json"},
                        body={"aliases": {alias: {"is_write_index": True}}})
                except RequestError as e:
                    if e.error == 'resource_already_exists_exception':
                        pass
                    else:
                        logger.exception(e.info)
                except Exception as e:
                    logger.exception(e.info)
            else:
                logger.debug(f"alias {alias} already exists")


def get_es_entries(logfile):
    """get opensearch entries.

    To return json to load OpenSearch Service, extract log, map fields to ecs
     fields and enrich ip addresses with geoip. Most important process.
    """
    # ETL対象のログタイプのConfigだけを限定して定義する
    logconfig = create_logconfig(logfile.logtype)
    # load custom script
    sf_module = utils.load_sf_module(logfile, logconfig, user_libs_list)

    logparser = siem.LogParser(
        logfile, logconfig, sf_module, geodb_instance, ioc_instance,
        xff_instance)
    for lograw, logdata, logmeta in logfile:
        logparser(lograw, logdata, logmeta)
        if logparser.is_ignored:
            logfile.excluded_log_count += 1
            if logparser.ignored_reason:
                logger.debug(
                    f'Skipped log because {logparser.ignored_reason}')
            continue
        indexname = utils.get_writable_indexname(
            logparser.indexname, READ_ONLY_INDICES)
        action_meta = {'index': {'_index': indexname, '_id': logparser.doc_id}}
        # logger.debug(logparser.json)
        yield [action_meta, logparser.json]

    del logparser


def check_es_results(results, total_count):
    duration = results['took']
    success, error = 0, 0
    error_reasons = []
    count = total_count
    retry = False
    if not results['errors']:
        success = len(results['items'])
    else:
        for result in results['items']:
            count += 1
            if result['index']['status'] >= 300:
                # status code
                # 200:OK, 201:Created
                # https://github.com/opensearch-project/OpenSearch/blob/1.3.0/server/src/main/java/org/opensearch/rest/RestStatus.java
                # https://github.com/opensearch-project/logstash-output-opensearch/blob/v1.2.0/lib/logstash/outputs/opensearch.rb#L32-L43
                if result['index']['status'] in (400, 409):
                    # 400: BAD_REQUEST such as mapper_parsing_exception
                    # 409: CONFLICT
                    pass
                else:
                    # 403: FORBIDDEN such as index_create_block_exception,
                    #      disk_full
                    # 429: TOO_MANY_REQUESTS
                    # 503: SERVICE_UNAVAILABLE
                    retry = True
                error += 1
                error_reason = result['index'].get('error')
                error_reason['log_number'] = count
                if error_reason:
                    error_reasons.append(error_reason)
            else:
                success += 1

    return duration, success, error, error_reasons, retry


def bulkloads_into_opensearch(es_entries, collected_metrics):
    global es_conn
    global docid_set
    output_size, total_output_size = 0, 0
    total_count, success_count, error_count, es_response_time = 0, 0, 0, 0
    results = False
    putdata_list = []
    error_reason_list = []
    retry_needed = False
    filter_path = ['took', 'errors', 'items.index.status', 'items.index.error']
    docid_list = []
    for data in es_entries:
        if AOSS_TYPE == 'TIMESERIES':
            docid = data[0]['index'].pop('_id')
            if docid in docid_set:
                continue
            docid_list.append(docid)
        action_meta = json.dumps(data[0])
        parsed_json = data[1]
        putdata_list.extend([action_meta, parsed_json])
        output_size += len(action_meta) + len(parsed_json)
        # es の http.max_content_length は t2 で10MB なのでデータがたまったらESにロード
        if output_size > 6000000:
            total_output_size += output_size
            try:
                results = es_conn.bulk(putdata_list, filter_path=filter_path)
            except (AuthorizationException, AuthenticationException) as err:
                logger.warning(
                    'AuthN or AuthZ Exception raised due to SigV4 issue. '
                    f'http_compress has been disabled. {err}')
                es_conn = utils.create_es_conn(
                    awsauth, ES_HOSTNAME, http_compress=False)
                results = es_conn.bulk(putdata_list, filter_path=filter_path)
            es_took, success, error, error_reasons, retry = check_es_results(
                results, total_count)
            success_count += success
            error_count += error
            es_response_time += es_took
            output_size = 0
            total_count = success_count + error_count
            putdata_list = []
            if len(error_reasons):
                error_reason_list.extend(error_reasons)
            if retry:
                retry_needed = True
    if output_size > 0:
        total_output_size += output_size
        try:
            results = es_conn.bulk(putdata_list, filter_path=filter_path)
        except (AuthorizationException, AuthenticationException) as err:
            logger.warning(
                'AuthN or AuthZ Exception raised due to SigV4 issue. '
                f'http_compress has been disabled. {err}')
            es_conn = utils.create_es_conn(
                awsauth, ES_HOSTNAME, http_compress=False)
            results = es_conn.bulk(putdata_list, filter_path=filter_path)
        # logger.debug(results)
        es_took, success, error, error_reasons, retry = check_es_results(
            results, total_count)
        success_count += success
        error_count += error
        es_response_time += es_took
        total_count = success_count + error_count
        if len(error_reasons):
            error_reason_list.extend(error_reasons)
        if retry:
            retry_needed = True
    if AOSS_TYPE == 'TIMESERIES':
        for error_reason in reversed(error_reason_list):
            del docid_list[error_reason['log_number'] - 1]
        docid_set.update(docid_list)
    collected_metrics['total_output_size'] = total_output_size
    collected_metrics['total_log_load_count'] = total_count
    collected_metrics['success_count'] = success_count
    collected_metrics['error_count'] = error_count
    collected_metrics['es_response_time'] = es_response_time

    return collected_metrics, error_reason_list, retry_needed


def output_metrics(metrics, logfile=None, collected_metrics={}):
    if not os.environ.get('AWS_EXECUTION_ENV'):
        return
    total_output_size = collected_metrics['total_output_size']
    success_count = collected_metrics['success_count']
    error_count = collected_metrics['error_count']
    excluded_log_count = logfile.excluded_log_count
    counted_log_count = logfile.counted_log_count
    es_response_time = collected_metrics['es_response_time']
    input_file_size = logfile.s3obj_size
    s3_key = logfile.s3key
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
        name="ExcludedLogCount", unit=MetricUnit.Count,
        value=excluded_log_count)
    metrics.add_metric(
        name="CountedLogCount", unit=MetricUnit.Count, value=counted_log_count)
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


def observability_decorator_switcher(func):
    if os.environ.get('AWS_EXECUTION_ENV'):
        @metrics.log_metrics
        @logger.inject_lambda_context(clear_state=True)
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


awsauth = utils.create_awsauth(ES_HOSTNAME)
es_conn = utils.create_es_conn(awsauth, ES_HOSTNAME)
if SERVICE == 'es':
    DOMAIN_INFO = es_conn.info()
    logger.info(DOMAIN_INFO)
    READ_ONLY_INDICES = utils.get_read_only_indices(
        es_conn, awsauth, ES_HOSTNAME)
    logger.info(json.dumps({'READ_ONLY_INDICES': READ_ONLY_INDICES}))
elif SERVICE == 'aoss':
    READ_ONLY_INDICES = ''
user_libs_list = utils.find_user_custom_libs()
etl_config = utils.get_etl_config()
utils.load_modules_on_memory(etl_config, user_libs_list)
logtype_s3key_dict = utils.create_logtype_s3key_dict(etl_config)
if SERVICE == 'es':
    check_and_create_aliases_if_needed(es_conn)
exclusion_conditions = utils.get_exclusion_conditions()

builtin_log_exclusion_patterns: dict = (
    utils.make_exclude_own_log_patterns(etl_config))
csv_filename = utils.get_exclude_log_patterns_csv_filename(etl_config)
custom_log_exclusion_patterns: dict = (
    utils.convert_csv_into_log_patterns(csv_filename))
log_exclusion_patterns: dict = utils.merge_log_exclusion_patterns(
    builtin_log_exclusion_patterns, custom_log_exclusion_patterns)
# e.g. log_exclusion_patterns['cloudtrail'] = [pattern1, pattern2]

s3_session_config = utils.make_s3_session_config(etl_config)
s3_client = boto3.client('s3', config=s3_session_config)
sqs_queue = utils.sqs_queue(SQS_SPLITTED_LOGS_URL)

control_tower_log_buckets = os.environ.get('CONTROL_TOWER_LOG_BUCKETS', '')
control_tower_log_bucket_list = (
    control_tower_log_buckets.replace(',', ' ').split())
control_tower_role_arn = os.environ.get('CONTROL_TOWER_ROLE_ARN')
control_tower_role_session_name = os.environ.get(
    'CONTROL_TOWER_ROLE_SESSION_NAME')
control_tower_s3_client = utils.get_s3_client_for_crosss_account(
    config=s3_session_config, role_arn=control_tower_role_arn,
    role_session_name=control_tower_role_session_name)

security_lake_log_buckets = os.environ.get('SECURITY_LAKE_LOG_BUCKETS', '')
security_lake_role_arn = os.environ.get('SECURITY_LAKE_ROLE_ARN')
security_lake_role_session_name = os.environ.get(
    'SECURITY_LAKE_ROLE_SESSION_NAME')
security_lake_external_id = os.environ.get('SECURITY_LAKE_EXTERNAL_ID')
security_lake_s3_client = utils.get_s3_client_for_crosss_account(
    config=s3_session_config, role_arn=security_lake_role_arn,
    role_session_name=security_lake_role_session_name,
    external_id=security_lake_external_id)

geodb_instance = geodb.GeoDB(s3_session_config)
ioc_instance = ioc.DB(s3_session_config)
xff_instance = xff.DB(s3_session_config)
utils.show_local_dir()


@observability_decorator_switcher
def lambda_handler(event, context):
    batch_item_failures = main(event, context)
    if batch_item_failures:
        return {"batchItemFailures": batch_item_failures}
    else:
        return None


def main(event, context):
    batch_item_failures = []
    if 'Records' in event:
        event_source = event['Records'][0].get('eventSource')
        error_code = event['Records'][0].get(
            'messageAttributes', {}).get('ErrorCode')
        if event_source == 'aws:s3':
            # s3 notification directly
            for record in event['Records']:
                process_record(record)
        elif event_source == 'aws:sqs' and error_code:
            # DLQ retrive
            for record in event['Records']:
                main(json.loads(record['body']), context)
        elif event_source == 'aws:sqs':
            # s3 notification from SQS
            for record in event['Records']:
                try:
                    recs = json.loads(record['body'])
                    if 'Records' in recs:
                        # Control Tower
                        for record in recs['Records']:
                            process_record(record)
                    else:
                        # from sqs-splitted-log, Security Lake(via EventBridge)
                        process_record(recs)
                except Exception:
                    batch_item_failures.append(
                        {"itemIdentifier": record['messageId']})
        elif event['Records'][0].get('EventSource') == 'aws:sns':
            # s3 notification from SNS
            for record in event['Records']:
                recs = json.loads(record['Sns']['Message'])
                for record in recs['Records']:
                    process_record(record)
        else:
            # local execution
            for record in event['Records']:
                process_record(record)
    elif (event.get('source') == 'aws.s3'
            and event.get('detail-type') == 'Object Created'):
        # s3 notification from EventBridge
        record = {'s3': event['detail']}
        process_record(record)
    return batch_item_failures


def process_record(record):
    collected_metrics = {'start_time': time.perf_counter()}
    # S3からファイルを取得してログを抽出する
    logfile = extract_logfile_from_s3(record)
    if logfile is None:
        return None
    elif logfile.is_ignored:
        if hasattr(logfile, 'ignored_reason') and logfile.ignored_reason:
            logger.warning(
                f'Skipped S3 object because {logfile.ignored_reason}')
        elif (hasattr(logfile, 'critical_reason')
                and logfile.critical_reason):
            logger.critical(
                f'Skipped S3 object because {logfile.critical_reason}')
        return None

    # 抽出したログからESにPUTするデータを作成する
    es_entries = get_es_entries(logfile)
    # 作成したデータをESにPUTしてメトリクスを収集する
    (collected_metrics, error_reason_list, retry_needed) = (
        bulkloads_into_opensearch(es_entries, collected_metrics))
    output_metrics(metrics, logfile=logfile,
                   collected_metrics=collected_metrics)
    if logfile.error_logs_count > 0:
        collected_metrics['error_count'] += logfile.error_logs_count
    if logfile.is_ignored:
        logger.warning(
            f'Skipped S3 object because {logfile.ignored_reason}')
    elif collected_metrics['error_count']:
        extra = None
        error_message = (f"{collected_metrics['error_count']} of logs "
                         "were NOT loaded into OpenSearch Service")
        if len(error_reason_list) > 0:
            extra = {'message_error': error_reason_list[:5]}
        logger.error(error_message, extra=extra)
        if retry_needed:
            logger.error('Aborted. It may be retried')
            raise
    elif collected_metrics['total_log_load_count'] > 0:
        logger.info('All logs were loaded into OpenSearch Service')
    else:
        logger.warning('No entries were successed to load')
    del logfile


if __name__ == '__main__':
    import argparse
    import traceback
    from datetime import datetime, timezone
    from functools import partial
    from multiprocessing import Pool

    print(__version__)

    def check_args():
        parser = argparse.ArgumentParser(description='es-loader',)
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument(
            '-b', '--s3bucket', help='s3 bucket where logs are storeed')
        parser.add_argument(
            '-l', '--s3list', help=('s3 object list which you want to load to '
                                    'OpenSearch Service. You can create the '
                                    'list by '
                                    '"aws s3 ls S3BUCKET --recursive"'))
        group.add_argument('-q', '--sqs', help='SQS queue name of DLQ')
        args = parser.parse_args()
        if args.s3bucket:
            if not args.s3list:
                print('You need to provide s3 object list with -l')
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
    else:
        outfile = None
        events = {}
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
