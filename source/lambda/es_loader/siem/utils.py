# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.6.1-beta.3'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import configparser
import csv
import importlib
import ipaddress
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from functools import lru_cache

import boto3
import botocore
import requests
from aws_lambda_powertools import Logger
from opensearchpy import OpenSearch, RequestsHttpConnection
from requests_aws4auth import AWS4Auth

logger = Logger(child=True)


#############################################################################
# text utils
#############################################################################
# REGEXP
RE_INSTANCEID = re.compile(
    r'(\W|_|^)(?P<instanceid>i-([0-9a-z]{8}|[0-9a-z]{17}))(\W|_|$)')
RE_ACCOUNT = re.compile(r'/([0-9]{12})/')
RE_REGION = re.compile(
    r'(global|(us|ap|ca|eu|me|sa|af|cn)-(gov-)?[a-zA-Z]+-[0-9])')
# for timestamp
RE_WITH_NANOSECONDS = re.compile(r'(.*)([0-9]{2}\.[0-9]{1,9})(.*)')
RE_SYSLOG_FORMAT = re.compile(r'([A-Z][a-z]{2})\s+(\d{1,2})\s+'
                              r'(\d{2}):(\d{2}):(\d{2})(\.(\d{1,6}))?')
MONTH_TO_INT = {'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
                'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12}
NOW = datetime.now(timezone.utc)
TD_OFFSET12 = timedelta(hours=12)
TIMEZONE_UTC = timezone(timedelta(hours=0))


@lru_cache(maxsize=1024)
def extract_aws_account_from_text(text):
    if text:
        m = RE_ACCOUNT.search(text)
        if m:
            return(m.group(1))
        else:
            return None


@lru_cache(maxsize=1024)
def extract_aws_region_from_text(text):
    if text:
        m = RE_REGION.search(text)
        if m:
            return(m.group(1))
        else:
            return None


@lru_cache(maxsize=1024)
def extract_aws_instanceid_from_text(text):
    if text:
        m = RE_INSTANCEID.search(text)
        if m:
            return(m.group(2))
        return None


def cluster_instance_identifier(logdata):
    try:
        log_group = logdata['@log_group'].split('/')
    except Exception:
        log_group = [None, None, None, None]

    if 'rds' not in logdata:
        logdata['rds'] = dict()
    identifier = {}
    identifier['cluster'], identifier['instance'] = (
        extract_rds_cluster_instance_identifier(
            log_group[3], log_group[4], logdata['@log_stream']))

    return identifier


@lru_cache(maxsize=1024)
def extract_rds_cluster_instance_identifier(
        log_group_3, log_group_4, log_stream):
    cluster_identifier = None
    instance_identifier = None
    if log_group_3 in ('instance', ):
        # ex)
        # dBInstanceIdentifier = database-1
        instance_identifier = log_group_4
    elif log_group_3 in ('cluster', ):
        # ex)
        # dBClusterIdentifier = database-1
        # dBInstanceIdentifier = database-1-instance-1
        cluster_identifier = log_group_4
        instance_identifier = log_stream.split('.')[0]
    return cluster_identifier, instance_identifier


def convert_underscore_field_into_dot_notation(prefix, logdata):
    if not prefix:
        return logdata
    if prefix not in logdata:
        logdata[prefix] = dict()
    prefix_underscore = prefix + '_'
    underscore_fields = []
    for field in logdata:
        if field.startswith(prefix_underscore):
            underscore_fields.append(field)
    for underscore_field in underscore_fields:
        new_key = underscore_field.replace(prefix_underscore, '')
        logdata[prefix][new_key] = logdata[underscore_field]
        del logdata[underscore_field]
    return logdata


@lru_cache(maxsize=100000)
def validate_ip(value, ecs_key):
    if '.ip' in ecs_key:
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            return None
    else:
        return value


#############################################################################
# date time
#############################################################################
def get_timestr_from_logdata_dict(logdata_dict, timestamp_key, has_nanotime):
    timestr = value_from_nesteddict_by_dottedkey(logdata_dict, timestamp_key)
    # 末尾がZはPythonでは対応していないのでカットしてTZを付与
    try:
        timestr = timestr.replace('Z', '+00:00')
    except AttributeError:
        # int such as epoch
        pass
    if has_nanotime:
        m = RE_WITH_NANOSECONDS.match(timestr)
        if m and m.group(3):
            microsec = m.group(2)[:9].ljust(9, '0')
            timestr = m.group(1) + microsec + m.group(3)
    return timestr


@lru_cache(maxsize=100000)
def convert_timestr_to_datetime(timestr, timestamp_key, timestamp_format, TZ):
    dt = None
    if 'epoch' in timestamp_format:
        dt = convert_epoch_to_datetime(timestr, TZ)
    elif 'syslog' in timestamp_format:
        dt = convert_syslog_to_datetime(timestr, TZ)
    elif 'iso8601' in timestamp_format:
        dt = convert_iso8601_to_datetime(timestr, TZ, timestamp_key)
    elif timestamp_format:
        dt = convert_custom_timeformat_to_datetime(
            timestr, TZ, timestamp_format, timestamp_key)
    return dt


@lru_cache(maxsize=1024)
def convert_epoch_to_datetime(timestr, TZ):
    epoch = float(timestr)
    if 1000000000000000 > epoch > 1000000000000:
        # milli epoch
        epoch_seconds = epoch / 1000.0
        dt = datetime.fromtimestamp(epoch_seconds, tz=TZ)
    elif epoch > 1000000000000000:
        # micro epoch
        epoch_seconds = epoch / 1000000.0
        dt = datetime.fromtimestamp(epoch_seconds, tz=TZ)
    else:
        # normal epoch
        dt = datetime.fromtimestamp(epoch, tz=TZ)
    return dt


@lru_cache(maxsize=1024)
def convrt_micro_epoch_to_seconds_epoch(obj):
    if isinstance(obj, str):
        try:
            obj_int = int(obj)
        except ValueError:
            return obj
        if obj_int > 1000000000000000:
            return int(obj) / 1000000.0
    return obj


@lru_cache(maxsize=10000)
def convert_syslog_to_datetime(timestr, TZ):
    now = NOW + TD_OFFSET12
    # timezoneを考慮して、12時間を早めた現在時刻を基準とする
    m = RE_SYSLOG_FORMAT.match(timestr)
    try:
        # コンマ以下の秒があったら
        microsec = int(m.group(7).ljust(6, '0'))
    except AttributeError:
        microsec = 0
    try:
        dt = datetime(
            year=now.year, month=MONTH_TO_INT[m.group(1)],
            day=int(m.group(2)), hour=int(m.group(3)), minute=int(m.group(4)),
            second=int(m.group(5)), microsecond=microsec, tzinfo=TZ)
    except ValueError:
        # うるう年対策
        last_year = now.year - 1
        dt = datetime(
            year=last_year, month=MONTH_TO_INT[m.group(1)],
            day=int(m.group(2)), hour=int(m.group(3)), minute=int(m.group(4)),
            second=int(m.group(5)), microsecond=microsec, tzinfo=TZ)
    if dt > now:
        # syslog timestamp が未来。マイナス1年の補正が必要
        # know_issue: 1年以上古いログの補正はできない
        last_year = now.year - 1
        dt = dt.replace(year=last_year)
    else:
        # syslog timestamp が過去であり適切。処理なし
        pass
    return dt


@lru_cache(maxsize=1024)
def convert_iso8601_to_datetime(timestr, TZ, timestamp_key):
    timestr = timestr.replace('+0000', '')
    # Python datetime.fromisoformat can't parser +0000 format.
    try:
        dt = datetime.fromisoformat(timestr)
    except ValueError:
        msg = (f'You set {timestamp_key} field as ISO8601 format. '
               f'Timestamp string is {timestr} and NOT ISO8601.')
        logger.exception(msg)
        raise ValueError(msg) from None
    if not dt.tzinfo:
        dt = dt.replace(tzinfo=TZ)
    return dt


@lru_cache(maxsize=10000)
def convert_custom_timeformat_to_datetime(timestr, TZ, timestamp_format,
                                          timestamp_key):
    try:
        dt = datetime.strptime(timestr, timestamp_format)
    except ValueError:
        msg = f'timestamp key {timestamp_key} is wrong'
        logger.exception(msg)
        raise ValueError(msg) from None
    if TZ and not dt.tzinfo:
        dt = dt.replace(tzinfo=TZ)
    return dt


#############################################################################
# Amazon OpenSearch Service / AWS Resouce
#############################################################################
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
            logger.error('You need to set ES_ENDPOINT in ENVRIONMENT '
                         'or modify aes.ini. exit')
            raise Exception('No ES_ENDPOINT in Environemnt')
    return es_hostname


def create_awsauth(es_hostname):
    es_region = es_hostname.split('.')[1]
    # For Debug
    # boto3.set_stream_logger('botocore', level='DEBUG')
    credentials = boto3.Session().get_credentials()
    service = 'es'
    awsauth = AWS4Auth(
        credentials.access_key, credentials.secret_key, es_region, service,
        session_token=credentials.token)
    return awsauth


def create_es_conn(awsauth, es_hostname):
    es_conn = OpenSearch(
        hosts=[{'host': es_hostname, 'port': 443}], http_auth=awsauth,
        use_ssl=True, http_compress=True, verify_certs=True,
        retry_on_timeout=True, connection_class=RequestsHttpConnection,
        timeout=60)
    return es_conn


def get_read_only_indices(es_conn, awsauth, ES_HOSTNAME):
    read_only_indices = []
    # cold tier
    # GET _cold/indices/_search?page_size=100
    url = f'https://{ES_HOSTNAME}/_cold/indices/_search'
    headers = {'Content-Type': 'application/json'}
    try:
        res = requests.get(
            url, params={'page_size': 1}, auth=awsauth, timeout=3.0)
    except requests.exceptions.Timeout:
        logger.warning('timeout: impossible to get cold index')
        return tuple(read_only_indices)
    while res.status_code == 200 and len(res.json()['indices']) > 0:
        for obj in res.json()['indices']:
            idx = obj['index']
            if idx.startswith('log-'):
                read_only_indices.append(idx)
        pagination_id = res.json()['pagination_id']
        body = f'{{"pagination_id": "{pagination_id}"}}'
        try:
            res = requests.post(
                url, data=body, auth=awsauth, headers=headers, timeout=3.0)
        except requests.exceptions.Timeout:
            logger.warning('timeout: impossible to get all cold index')
            break

    # close index
    # params = {'index': 'log-*', 'h': 'index,status'}
    # indices = es_conn.cat.indices(params=params)

    # close index and ultrawarm tier
    indices = es_conn.cluster.state(metric='blocks')
    if ('blocks' in indices) and ('indices' in indices['blocks']):
        for idx in indices['blocks']['indices']:
            if idx.startswith('log-'):
                read_only_indices.append(idx)
    return tuple(sorted(list(set(read_only_indices))))


@lru_cache(maxsize=1024)
def get_writable_indexname(indexname, READ_ONLY_INDICES):
    if indexname not in READ_ONLY_INDICES:
        return indexname
    else:
        m = re.match('(log-.*)_([0-9]{2})', indexname)
        if m:
            org_indexname = m.group(1)
            suffix = int(m.group(2))
        else:
            org_indexname = indexname
            suffix = 1
        new_indexname = f'{org_indexname}_{suffix:02}'
        while new_indexname in READ_ONLY_INDICES:
            suffix += 1
            new_indexname = f'{org_indexname}_{suffix:02}'
        logger.warning(f'{indexname} is close, ultrawarm or cold index. '
                       f'New index name is {new_indexname}')
        return new_indexname


def create_logtype_s3key_dict(etl_config):
    logtype_s3key_dict = {}
    for logtype in etl_config.sections():
        logtype_s3key_dict[logtype] = re.compile(etl_config[logtype]['s3_key'])
    return logtype_s3key_dict


def get_logtype_from_s3key(s3key, logtype_s3key_dict):
    if s3key[-1] == '/':
        return 'nodata'
    for logtype, re_s3key in logtype_s3key_dict.items():
        m = re_s3key.search(s3key)
        if m:
            return logtype
    return 'unknown'


def sqs_queue(queue_url):
    if not queue_url:
        return None
    try:
        sqs_resource = boto3.resource('sqs', endpoint_url=queue_url)
        sqs_queue = sqs_resource.Queue(queue_url)
    except Exception:
        logger.exception(f'impossible to connect SQS {queue_url}')
        raise Exception(f'impossible to connect SQS {queue_url}') from None
    return sqs_queue


#############################################################################
# Lambda initialization
#############################################################################
def find_user_custom_libs():
    # /opt is mounted by lambda layer
    user_libs = []
    if os.path.isdir('/opt/siem'):
        user_libs = [i for i in os.listdir('/opt/siem/') if 'sf_' in i]
        sys.path.append('/opt/siem')
    return user_libs


@lru_cache(maxsize=128)
def timestr_to_hours(timestr):
    try:
        hours, minutes = timestr.split(':')
        hours = int(hours) + int(minutes) / 60
    except ValueError:
        hours = timestr
    except Exception:
        logger.exception(f'impossible to convert {timestr} to hours')
        raise Exception(f'impossible to convert {timestr} to hours') from None
    return str(hours)


def get_etl_config():
    etl_config = configparser.ConfigParser(
        interpolation=configparser.ExtendedInterpolation())
    etl_config.optionxform = str
    siem_dir = os.path.dirname(__file__)
    etl_config.read(f'{siem_dir}/../aws.ini')
    # overwride with user configration
    etl_config.read('/opt/user.ini')
    etl_config.read(f'{siem_dir}/../user.ini')
    etl_config.sections()
    if 'doc_id' not in etl_config['DEFAULT']:
        logger.error('invalid config file: aws.ini. exit')
        raise Exception('invalid config file: aws.ini. exit')
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


def load_sf_module(logfile, logconfig, user_libs_list):
    if logconfig['script_ecs']:
        mod_name = 'sf_' + logfile.logtype.replace('-', '_')
        # old_mod_name is for compatibility
        old_mod_name = 'sf_' + logfile.logtype
        if mod_name + '.py' in user_libs_list:
            sf_module = importlib.import_module(mod_name)
        elif old_mod_name + '.py' in user_libs_list:
            sf_module = importlib.import_module(old_mod_name)
        else:
            sf_module = importlib.import_module('siem.' + mod_name)
    else:
        sf_module = None
    return sf_module


def make_exclude_own_log_patterns(etl_config):
    log_patterns = {}
    if etl_config['DEFAULT'].getboolean('ignore_own_logs'):
        user_agent = etl_config['DEFAULT'].get('custom_user_agent', '')
        if user_agent:
            re_user_agent = re.compile('.*' + re.escape(user_agent) + '.*')
            log_patterns['cloudtrail'] = {'userAgent': re_user_agent}
            log_patterns['s3accesslog'] = {'UserAgent': re_user_agent}
    return log_patterns


def get_exclude_log_patterns_csv_filename(etl_config):
    csv_filename = etl_config['DEFAULT'].get('exclude_log_patterns_filename')
    if not csv_filename:
        return None
    if 'GEOIP_BUCKET' in os.environ:
        geoipbucket = os.environ.get('GEOIP_BUCKET', '')
    else:
        config = configparser.ConfigParser(
            interpolation=configparser.ExtendedInterpolation())
        config.read('aes.ini')
        config.sections()
        if 'aes' in config:
            geoipbucket = config['aes']['GEOIP_BUCKET']
        else:
            return None
    s3geo = boto3.resource('s3')
    bucket = s3geo.Bucket(geoipbucket)
    s3obj = csv_filename
    local_file = f'/tmp/{csv_filename}'
    try:
        bucket.download_file(s3obj, local_file)
    except Exception:
        return None
    return local_file


def merge_dotted_key_value_into_dict(patterns_dict, dotted_key, value):
    if not patterns_dict:
        patterns_dict = {}
    patterns_dict_temp = patterns_dict
    key_list = dotted_key.split('.')
    for key in key_list[:-1]:
        patterns_dict_temp = patterns_dict_temp.setdefault(key, {})
    patterns_dict_temp[key_list[-1]] = value
    return patterns_dict


def merge_csv_into_log_patterns(log_patterns, csv_filename):
    if not csv_filename:
        logger.info(f'{log_patterns}')
        return log_patterns
    logger.info(f'{csv_filename} is imported to exclude_log_patterns')
    with open(csv_filename, 'rt') as f:
        for line in csv.DictReader(f):
            if line['pattern_type'].lower() == 'text':
                pattern = re.compile(str(re.escape(line['pattern'])) + '$')
            else:
                pattern = re.compile(str(line['pattern']) + '$')
            log_patterns.setdefault(line['log_type'], {})
            log_patterns[line['log_type']] = merge_dotted_key_value_into_dict(
                log_patterns[line['log_type']],
                line['field'], pattern)
    logger.info(f'{log_patterns}')
    return log_patterns


def make_s3_session_config(etl_config):
    user_agent = etl_config['DEFAULT'].get('custom_user_agent', '')
    user_agent_ver = etl_config['DEFAULT'].get('custom_user_agent_ver', '')
    if user_agent:
        s3_session_config = botocore.config.Config(
            user_agent=f'{user_agent}/{user_agent_ver}')
    else:
        s3_session_config = None
    return s3_session_config


def show_local_dir():
    target_dirname = ['/tmp', '/opt', '/opt/siem']
    for dirname in target_dirname:
        if os.path.isdir(dirname):
            logger.info({'directory': dirname,
                         'files': str(os.listdir(path=dirname))})


#############################################################################
# log utils
#############################################################################
def get_mime_type(data):
    if data.startswith(b'\x1f\x8b'):
        return 'gzip'
    elif data.startswith(b'\x50\x4b'):
        return 'zip'
    elif data.startswith(b'\x42\x5a'):
        return 'bzip2'
    textchars = bytearray(
        {7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7f})
    if bool(data.translate(None, textchars)):
        return 'binary'
    else:
        return 'text'


def value_from_nesteddict_by_dottedkey(nested_dict, dotted_key):
    """get value form nested dict by dotted key.

    入れ子になった辞書nested_dictに対して、dotを含んだdotted_keyで値を抽出する

    >>> nested_dict = {'a': {'b': {'c': 123}}}
    >>> dotted_key = 'a.b.c'
    >>> value_from_nesteddict_by_dottedkey(nested_dict, dotted_key)
    123
    >>> dotted_key = 'a.b'
    >>> value_from_nesteddict_by_dottedkey(nested_dict, dotted_key)
    {'c': 123}
    >>> dotted_key = 'x.y.z'
    >>> value_from_nesteddict_by_dottedkey(nested_dict, dotted_key)

    >>> nested_dict = {'a': {'b': [{'d0': 123}, {'d1': 456}]}}
    >>> dotted_key = 'a.b.0.d0'
    >>> value_from_nesteddict_by_dottedkey(nested_dict, dotted_key)
    123
    """
    value = nested_dict
    for key in dotted_key.split('.'):
        if key.isdigit():
            key = int(key)
        try:
            value = value[key]
        except (TypeError, KeyError, IndexError):
            value = ''
            break
    if value:
        return value


def value_from_nesteddict_by_dottedkeylist(nested_dict, dotted_key_list):
    """get value form nested dict by dotted key list.

    get the values in loop and return 1st value
    >>> nested_dict = {'a': {'b': {'c1': 123, 'c2': 456}}}
    >>> dotted_key_list = 'a.b.c1 a.b.c2'
    >>> value_from_nesteddict_by_dottedkeylist(nested_dict, dotted_key_list)
    123
    >>> dotted_key_list = 'a.b.c2 a.b.c1'
    >>> value_from_nesteddict_by_dottedkeylist(nested_dict, dotted_key_list)
    456
    >>> dotted_key_list = 'z.z.z.z.z.z a.b.c1 a.b.c2'
    >>> value_from_nesteddict_by_dottedkeylist(nested_dict, dotted_key_list)
    123
    """
    if isinstance(dotted_key_list, str):
        dotted_key_list = dotted_key_list.split()
    elif isinstance(dotted_key_list, list):
        pass
    for dotted_key in dotted_key_list:
        value = value_from_nesteddict_by_dottedkey(nested_dict, dotted_key)
        if value:
            return value


def put_value_into_nesteddict(dotted_key, value):
    """put value into nested dict by dotted key.

    dictのkeyにドットが含まれている場合に入れ子になったdictを作成し、
    値としてvalueを返す。返値はdictタイプ。vが辞書ならさらに入れ子として代入。
    >>> put_value_into_nesteddict('a', 123)
    {'a': '123'}
    >>> put_value_into_nesteddict('a.b.c.d.e', 123)
    {'a': {'b': {'c': {'d': {'e': '123'}}}}}
    >>> put_value_into_nesteddict('a.b.c', [123])
    {'a': {'b': {'c': [123]}}}
    >>> put_value_into_nesteddict('a.b.c', [123, 456])
    {'a': {'b': {'c': [123, 456]}}}
    >>> put_value_into_nesteddict('a.b.c', {'x': 1, 'y': 2})
    {'a': {'b': {'c': {'x': 1, 'y': 2}}}}
    >>> put_value_into_nesteddict('a.b.c', '"')
    {'a': {'b': {'c': '"'}}}
    """
    if (isinstance(value, dict) or isinstance(value, str)
            or isinstance(value, list)):
        value = value
    else:
        value = str(value)
    nested_dict = {}
    keys, current = dotted_key.split('.'), nested_dict
    for p in keys[:-1]:
        current[p] = {}
        current = current[p]

    current[keys[-1]] = value
    return nested_dict


def convert_keyname_to_safe_field(obj):
    """convert keyname into safe field name.

    when dict key include dash(-), convert to safe field name under_score(_).
    """
    if isinstance(obj, dict):
        for org_key in list(obj.keys()):
            new_key = org_key
            if '-' in org_key:
                new_key = org_key.translate({ord('-'): ord('_')})
                obj[new_key] = obj.pop(org_key)
            convert_keyname_to_safe_field(obj[new_key])
    elif isinstance(obj, list):
        for val in obj:
            convert_keyname_to_safe_field(val)
    else:
        pass
    return obj


def match_log_with_exclude_patterns(log_dict, log_patterns, ex_pattern=None):
    """match log with exclude patterns.

    ログと、log_patterns を比較させる
    一つでもマッチングされれば、OpenSearch ServiceにLoadしない

    >>> pattern1 = 111
    >>> RE_BINGO = re.compile('^'+str(pattern1)+'$')
    >>> pattern2 = 222
    >>> RE_MISS = re.compile('^'+str(pattern2)+'$')
    >>> log_patterns = { \
    'a': RE_BINGO, 'b': RE_MISS, 'x': {'y': {'z': RE_BINGO}}}
    >>> log_dict = {'a': 111}
    >>> match_log_with_exclude_patterns(log_dict, log_patterns)
    (True, '{a: 111}')
    >>> log_dict = {'a': 21112}
    >>> match_log_with_exclude_patterns(log_dict, log_patterns)
    (False, None)
    >>> log_dict = {'a': '111'}
    >>> match_log_with_exclude_patterns(log_dict, log_patterns)
    (True, '{a: 111}')
    >>> log_dict = {'aa': 222, 'a': 111}
    >>> match_log_with_exclude_patterns(log_dict, log_patterns)
    (True, '{a: 111}')
    >>> log_dict = {'x': {'y': {'z': 111}}}
    >>> match_log_with_exclude_patterns(log_dict, log_patterns)
    (True, '{z: 111}')
    >>> log_dict = {'x': {'y': {'z': 222}}}
    >>> match_log_with_exclude_patterns(log_dict, log_patterns)
    (False, None)
    >>> log_dict = {'x': {'hoge':222, 'y': {'z': 111}}}
    >>> match_log_with_exclude_patterns(log_dict, log_patterns)
    (True, '{z: 111}')
    >>> log_dict = {'a': 222}
    >>> match_log_with_exclude_patterns(log_dict, log_patterns)
    (False, None)

    """
    for key, pattern in log_patterns.items():
        if key in log_dict:
            if isinstance(pattern, dict) and isinstance(log_dict[key], dict):
                res, ex_pattern = match_log_with_exclude_patterns(
                    log_dict[key], pattern)
                return(res, ex_pattern)
            elif isinstance(pattern, re.Pattern):
                if isinstance(log_dict[key], list):
                    return(False, None)
                elif pattern.match(str(log_dict[key])):
                    ex_pattern = '{{{0}: {1}}}'.format(key, log_dict[key])
                    return(True, ex_pattern)
    return(False, None)


def merge_dicts(dicta, dictb, path=None):
    """merge two dicts.

    Merge dicta and dictb, then create new dict.
    When conflicts, override dicta as dictb.

    >>> dicta = {'a': 1, 'b': 2}
    >>> dictb = {'b': 3, 'c': 4}
    >>> merge_dicts(dicta, dictb)
    {'a': 1, 'b': 3, 'c': 4}

    >>> dicta = {'a': 1, 'b': {'x': 10, 'z': 30}}
    >>> dictb = {'b': {'x': 10, 'y': 20}, 'c': 4}
    >>> merge_dicts(dicta, dictb)
    {'a': 1, 'b': {'x': 10, 'z': 30, 'y': 20}, 'c': 4}

    """
    if path is None:
        path = []
    for key in dictb:
        if key in dicta:
            if isinstance(dicta[key], dict) and isinstance(dictb[key], dict):
                merge_dicts(dicta[key], dictb[key], path + [str(key)])
            elif dicta[key] == dictb[key]:
                pass  # same leaf value
            # elif str(dicta[key]) in str(dictb[key]):
            #    # strで上書き。JSONだったのをstrに変換したデータ
            #    dicta[key] = dictb[key]
            else:
                # conflict and override original value with new one
                dicta[key] = dictb[key]
        else:
            dicta[key] = dictb[key]
    return dicta


def dev_merge_dicts(dicta: dict, dictb: dict):
    """merge two dicts.

    under development.
    """
    if not isinstance(dicta, dict) or not isinstance(dictb, dict):
        return dicta
    new_dicta = {**dicta, **dictb}
    for k, v in new_dicta.items():
        if isinstance(v, dict):
            if (k in dicta) and isinstance(dicta[k], dict):
                if dicta[k] != v:
                    new_dicta[k] = dev_merge_dicts(dicta[k], v)
    return new_dicta
