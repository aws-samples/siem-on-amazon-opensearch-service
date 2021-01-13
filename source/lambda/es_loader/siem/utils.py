# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import configparser
import csv
from datetime import timedelta
import importlib
import json
import os
import re
import sys

from aws_lambda_powertools import Logger
import boto3
import botocore
from elasticsearch import Elasticsearch, RequestsHttpConnection
from requests_aws4auth import AWS4Auth

__version__ = '2.2.0-beta.2'

logger = Logger(child=True)


#############################################################################
# text utils
#############################################################################
# REGEXP
RE_INSTANCEID = re.compile(r'\W?(?P<instanceid>i-[0-9a-z]{8,17})\W?')
RE_ACCOUNT = re.compile(r'/([0-9]{12})/')
RE_REGION = re.compile('(global|(us|ap|ca|eu|me|sa|af)-[a-zA-Z]+-[0-9])')
# for timestamp
RE_WITH_NANOSECONDS = re.compile(r'(.*)([0-9]{2}\.[0-9]{1,9})(.*)')
RE_SYSLOG_FORMAT = re.compile(r'([A-Z][a-z]{2})\s+(\d{1,2})\s+'
                              r'(\d{2}):(\d{2}):(\d{2})(\.(\d{1,6}))?')
MONTH_TO_INT = {'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
                'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12}
TD_OFFSET12 = timedelta(hours=12)


def extract_aws_account_from_text(text):
    m = RE_ACCOUNT.search(text)
    if m:
        return(m.group(1))
    else:
        return None


def extract_aws_region_from_text(text):
    m = RE_REGION.search(text)
    if m:
        return(m.group(1))
    else:
        return None


def extract_aws_instanceid_from_text(text):
    m = RE_INSTANCEID.search(text)
    if m:
        return(m.group(1))
    else:
        return None


#############################################################################
# Amazon ES
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


#############################################################################
# initalize when lambda cold boot
#############################################################################
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
    user_libs = []
    if os.path.isdir('/opt/siem'):
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
        logger.exception(f'impossible to convert {timestr} to hours')
        raise Exception(f'impossible to convert {timestr} to hours') from None
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


def get_value_from_dict(dct, xkeys_list):
    """ 入れ子になった辞書に対して、dotを含んだkeyで値を
    抽出する。keyはリスト形式で複数含んでいたら分割する。
    値がなければ返値なし

    >>> dct = {'a': {'b': {'c': 123}}}
    >>> xkey = 'a.b.c'
    >>> get_value_from_dict(dct, xkey)
    123
    >>> xkey = 'x.y.z'
    >>> get_value_from_dict(dct, xkey)

    >>> xkeys_list = 'a.b.c x.y.z'
    >>> get_value_from_dict(dct, xkeys_list)
    123
    >>> dct = {'a': {'b': [{'c': 123}, {'c': 456}]}}
    >>> xkeys_list = 'a.b.0.c'
    >>> get_value_from_dict(dct, xkeys_list)
    123
    """
    for xkeys in xkeys_list.split():
        v = dct
        for k in xkeys.split('.'):
            try:
                k = int(k)
            except ValueError:
                pass
            try:
                v = v[k]
            except (TypeError, KeyError, IndexError):
                v = ''
                break
        if v:
            return v


def put_value_into_dict(key_str, v):
    """dictのkeyにドットが含まれている場合に入れ子になったdictを作成し、値としてvを入れる.
    返値はdictタイプ。vが辞書ならさらに入れ子として代入。
    値がlistなら、カンマ区切りのCSVにした文字列に変換
    TODO: 値に"が入ってると例外になる。対処方法が見つからず返値なDROPPEDにしてるので改善する。#34

    >>> put_value_into_dict('a.b.c', 123)
    {'a': {'b': {'c': '123'}}}
    >>> put_value_into_dict('a.b.c', [123])
    {'a': {'b': {'c': '123'}}}
    >>> put_value_into_dict('a.b.c', [123, 456])
    {'a': {'b': {'c': '123,456'}}}
    >>> v = {'x': 1, 'y': 2}
    >>> put_value_into_dict('a.b.c', v)
    {'a': {'b': {'c': {'x': 1, 'y': 2}}}}
    >>> v = str({'x': "1", 'y': '2"3'})
    >>> put_value_into_dict('a.b.c', v)
    {'a': {'b': {'c': 'DROPPED'}}}
    """
    v = v
    xkeys = key_str.split('.')
    if isinstance(v, dict):
        json_data = r'{{"{0}": {1} }}'.format(xkeys[-1], json.dumps(v))
    elif isinstance(v, list):
        json_data = r'{{"{0}": "{1}" }}'.format(
            xkeys[-1], ",".join(map(str, v)))
    else:
        json_data = r'{{"{0}": "{1}" }}'.format(xkeys[-1], v)
    if len(xkeys) >= 2:
        xkeys.pop()
        for xkey in reversed(xkeys):
            json_data = r'{{"{0}": {1} }}'.format(xkey, json_data)
    try:
        new_dict = json.loads(json_data, strict=False)
    except json.decoder.JSONDecodeError:
        new_dict = put_value_into_dict(key_str, 'DROPPED')
    return new_dict


def conv_key(obj):
    """dictのkeyに-が入ってたら_に置換する
    """
    if isinstance(obj, dict):
        for org_key in list(obj.keys()):
            new_key = org_key
            if '-' in org_key:
                new_key = org_key.translate({ord('-'): ord('_')})
                obj[new_key] = obj.pop(org_key)
            conv_key(obj[new_key])
    elif isinstance(obj, list):
        for val in obj:
            conv_key(val)
    else:
        pass


def merge(a, b, path=None):
    """merges b into a

    This function is DEPRECATED. Moved to siem.utils.merge_dicts.
    """
    if path is None:
        path = []
    for key in b:
        if key in a:
            if isinstance(a[key], dict) and isinstance(b[key], dict):
                merge(a[key], b[key], path + [str(key)])
            elif a[key] == b[key]:
                pass  # same leaf value
            elif str(a[key]) in str(b[key]):
                # strで上書き。JSONだったのをstrに変換したデータ
                a[key] = b[key]
            else:
                # conflict and override original value with new one
                a[key] = b[key]
        else:
            a[key] = b[key]
    return a


def match_log_with_exclude_patterns(log_dict, log_patterns):
    """ログと、log_patterns を比較させる
    一つでもマッチングされれば、Amazon ESにLoadしない

    >>> pattern1 = 111
    >>> RE_BINGO = re.compile('^'+str(pattern1)+'$')
    >>> pattern2 = 222
    >>> RE_MISS = re.compile('^'+str(pattern2)+'$')
    >>> log_patterns = { \
    'a': RE_BINGO, 'b': RE_MISS, 'x': {'y': {'z': RE_BINGO}}}
    >>> log_dict = {'a': 111}
    >>> match_log_with_exclude_patterns(log_dict, log_patterns)
    True
    >>> log_dict = {'a': 21112}
    >>> match_log_with_exclude_patterns(log_dict, log_patterns)

    >>> log_dict = {'a': '111'}
    >>> match_log_with_exclude_patterns(log_dict, log_patterns)
    True
    >>> log_dict = {'aa': 222, 'a': 111}
    >>> match_log_with_exclude_patterns(log_dict, log_patterns)
    True
    >>> log_dict = {'x': {'y': {'z': 111}}}
    >>> match_log_with_exclude_patterns(log_dict, log_patterns)
    True
    >>> log_dict = {'x': {'y': {'z': 222}}}
    >>> match_log_with_exclude_patterns(log_dict, log_patterns)

    >>> log_dict = {'x': {'hoge':222, 'y': {'z': 111}}}
    >>> match_log_with_exclude_patterns(log_dict, log_patterns)
    True
    >>> log_dict = {'a': 222}
    >>> match_log_with_exclude_patterns(log_dict, log_patterns)

    """
    for key, pattern in log_patterns.items():
        if key in log_dict:
            if isinstance(pattern, dict) and isinstance(log_dict[key], dict):
                res = match_log_with_exclude_patterns(log_dict[key], pattern)
                return res
            elif isinstance(pattern, re.Pattern):
                if isinstance(log_dict[key], list):
                    pass
                elif pattern.match(str(log_dict[key])):
                    return True


def merge_dicts(dicta, dictb, path=None):
    """merge two dicts.

    Merge dicta and dictb, then create new dict.
    When conflicts, override dicta as dictb.

    >>> dicta = {'a': 1, 'b': 2}
    >>> dictb = {'b': 3, 'c': 4}
    >>> merge_dicta_into_dictb(dicta, dictb)
    {'a': 1, 'b': 3, 'c': 4}

    >>> dicta = {'a': 1, 'b': {'x': 10, 'z': 30}}
    >>> dictb = {'b': {'x': 10, 'y': 20}, 'c': 4}
    >>> merge_dicta_into_dictb(dicta, dictb)
    {'a': 1, 'b': {'x': 10, 'y': 20, 'z': 30}, 'c': 4}

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
    """merge two dicts. under develoment.
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
