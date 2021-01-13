# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import base64
import bz2
from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import io
import ipaddress
import json
import re
import zipfile

from aws_lambda_powertools import Logger
import boto3

import index as es_loader
from siem import utils

__version__ = '2.2.0-beta.2'

logger = Logger(child=True)


class LogObj:
    """ 取得した一連のログファイルから表層的な情報を取得する。
    圧縮の有無の判断、ログ種類を判断、フォーマットの判断をして
    最後に、生ファイルを個々のログに分割してリスト型として返す
    """
    def __init__(self, config):
        self.config = config
        self.s3bucket = None
        self.s3key = None
        self.loggroup = None
        self.logstream = None
        self.via_cwl = None
        self.via_firelens = None
        self.s3key_accountid = None
        self.cwl_accountid = None
        self.cwe_accountid = None
        self.s3key_region = None
        self.cwe_region = None

    @property
    def header(self):
        return None

    def check_cwe_and_strip_header(self, dict_obj):
        if "detail-type" in dict_obj and "resources" in dict_obj:
            self.cwe_accountid = dict_obj['account']
            self.cwe_region = dict_obj['region']
            # source = dict_obj['source'] # eg) aws.securityhub
            # time = dict_obj['time'] #@ingested
            return dict_obj['detail']
        else:
            return dict_obj


class LogS3(LogObj):
    """ 取得した一連のログファイルから表層的な情報を取得する。
    圧縮の有無の判断、ログ種類を判断、フォーマットの判断をして
    最後に、生ファイルを個々のログに分割してリスト型として返す
    """
    def __init__(self, record, config, s3):
        # Get the bucket name and key for the new file
        super().__init__(config)
        self.s3 = s3
        self.s3bucket = record['s3']['bucket']['name']
        self.s3key = record['s3']['object']['key']
        try:
            self.start_number = record['siem']['start_number']
            self.end_number = record['siem']['end_number']
        except KeyError:
            self.start_number = 0
            self.end_number = 0
        self.total_log_count = 0
        self.config = config
        self.ignore = self.check_ignore()
        self.msgformat = 's3'
        if not self.ignore:
            self.s3key_accountid = utils.extract_aws_account_from_text(
                self.s3key)
            self.s3key_region = utils.extract_aws_region_from_text(self.s3key)
            self.__rawdata = self.extract_rawdata_from_s3obj()
            self.file_format = self.config[self.logtype]['file_format']
            self.via_cwl = self.config[self.logtype].getboolean('via_cwl')
            self.via_firelens = self.config[self.logtype].getboolean(
                'via_firelens')
        if self.via_cwl:
            self.loggroup, self.logstream, self.cwl_accountid = (
                self.extract_header_from_cwl(self.__rawdata))

    def check_ignore(self):
        if 'unknown' in self.logtype:
            # 対応していないlogtypeはunknownになる。その場合は処理をスキップさせる
            return f'Unknown log type in S3 key, {self.s3key}'
        else:
            s3_key_ignored = self.config[self.logtype]['s3_key_ignored']
            if s3_key_ignored:
                m = re.search(s3_key_ignored, self.s3key)
                if m:
                    return (f'"s3_key_ignored" {s3_key_ignored} matched with '
                            f'{self.s3key}')
        return False

    def extract_rawdata_from_s3obj(self):
        obj = self.s3.get_object(Bucket=self.s3bucket, Key=self.s3key)
        # if obj['ResponseMetadata']['HTTPHeaders']['content-length'] == '0':
        #    raise Exception('No Contents in s3 object')
        rawbody = io.BytesIO(obj['Body'].read())
        mime = utils.get_mime_type(rawbody.read(16))
        rawbody.seek(0)
        if mime == 'gzip':
            body = gzip.open(rawbody, mode='rt', encoding='utf8',
                             errors='ignore')
        elif mime == 'text':
            body = io.TextIOWrapper(rawbody, encoding='utf8', errors='ignore')
        elif mime == 'zip':
            z = zipfile.ZipFile(rawbody)
            body = open(z.namelist()[0], encoding='utf8', errors='ignore')
        elif mime == 'bzip2':
            body = bz2.open(rawbody, mode='rt', encoding='utf8',
                            errors='ignore')
        else:
            logger.error('unknown file format')
            raise Exception('unknown file format')
        return body

    def extract_header_from_cwl(self, rawdata):
        index = 0
        body = rawdata
        decoder = json.JSONDecoder()
        while True:
            obj, offset = decoder.raw_decode(str(body.read()))
            index = offset + index
            body.seek(index)
            if 'CONTROL_MESSAGE' in obj['messageType']:
                continue
            loggroup = obj['logGroup']
            logstream = obj['logStream']
            owner = obj['owner']
            return loggroup, logstream, owner

    def extract_messages_from_cwl(self, rawlog_io_obj):
        decoder = json.JSONDecoder()
        size = len(rawlog_io_obj.read())
        index = 0
        rawlog_io_obj.seek(index)
        newlog_io_obj = io.StringIO()
        while size > index:
            obj, offset = decoder.raw_decode(str(rawlog_io_obj.read()))
            index = offset + index
            rawlog_io_obj.seek(index)
            if 'CONTROL_MESSAGE' in obj['messageType']:
                continue
            for log in obj['logEvents']:
                newlog_io_obj.write(log['message'] + "\n")
        del rawlog_io_obj
        newlog_io_obj.seek(0)
        return newlog_io_obj

    @property
    def logtype(self):
        for section in self.config.sections():
            p = self.config[section]['s3_key']
            if re.search(p, self.s3key):
                return section
        else:
            return 'unknown'

    @property
    def accountid(self):
        if self.cwl_accountid:
            return self.cwl_accountid
        elif self.cwe_accountid:
            return self.cwe_accountid
        elif self.s3key_accountid:
            return self.s3key_accountid
        else:
            return None

    @property
    def region(self):
        if self.cwe_region:
            return self.cwe_region
        elif self.s3key_region:
            return self.s3key_region
        else:
            return None

    @property
    def rawdata(self):
        self.__rawdata.seek(0)
        if self.via_cwl:
            return self.extract_messages_from_cwl(self.__rawdata)
        return self.__rawdata

    @property
    def header(self):
        if 'csv' in self.file_format:
            return self.rawdata.readlines()[0].strip()
        else:
            return None

    def extract_logobj_from_json(self, mode='count', start=0, end=0,
                                 log_count=0, max_log_count=0):
        if start == 0 and es_loader.SQS_SPLITTED_LOGS_URL:
            end = max_log_count
        if start == 0 or max_log_count == 0:
            end = log_count
        decoder = json.JSONDecoder()
        delimiter = self.config[self.logtype]['json_delimiter']
        count = 0
        # For ndjson
        for line in self.rawdata.readlines():
            # for Firehose's json (multiple jsons in 1 line)
            size = len(line)
            index = 0
            while index < size:
                raw_event, offset = decoder.raw_decode(line, index)
                raw_event = self.check_cwe_and_strip_header(raw_event)
                if delimiter and (delimiter in raw_event):
                    # multiple evets in 1 json
                    for record in raw_event[delimiter]:
                        count += 1
                        if 'count' not in mode:
                            if start <= count <= end:
                                yield record
                elif not delimiter:
                    count += 1
                    if 'count' not in mode:
                        if start <= count <= end:
                            yield raw_event
                search = json.decoder.WHITESPACE.search(line, offset)
                if search is None:
                    break
                index = search.end()
            if 'count' in mode:
                yield count

    def split_logs_to_sqs(self, log_count, max_log_count):
        if self.start_number == 0 and es_loader.SQS_SPLITTED_LOGS_URL:
            if max_log_count and (log_count > max_log_count):
                pass
            else:
                return None
        else:
            return None
        sqs_client = boto3.client("sqs")
        queue_url = es_loader.SQS_SPLITTED_LOGS_URL
        q, mod = divmod(log_count, max_log_count)
        logger.debug({'split_logs': f's3://{self.s3bucket}/{self.s3key}',
                      'max_log_count': max_log_count, 'log_count': log_count})
        entries = []
        for x in range(q):
            start = (x + 1) * max_log_count + 1
            end = (x + 2) * max_log_count
            if (x + 1) == q:
                end = log_count
            queue_body = {
                "siem": {"start_number": start, "end_number": end},
                "s3": {"bucket": {"name": self.s3bucket},
                       "object": {"key": self.s3key}}}
            message_body = json.dumps(queue_body)
            logger.debug(message_body)
            entries.append({'Id': f'num_{start}', 'MessageBody': message_body})
            if (x % 10 == 9) or (x + 1 == q):
                response = sqs_client.send_message_batch(
                    QueueUrl=queue_url, Entries=entries)
                if response['ResponseMetadata']['HTTPStatusCode'] != 200:
                    logger.error(json.dumps(response))
                    raise Exception(json.dumps(response))
                entries = []
        return True

    @property
    def logdata_list(self):
        max_log_count = self.config[self.logtype].getint('max_log_count')

        if self.file_format in ('text', 'csv') or self.via_firelens:
            if 'text' in self.file_format:
                ignore_header_line_number = int(
                    self.config[self.logtype]['text_header_line_number'])
            elif 'csv' in self.file_format:
                ignore_header_line_number = 1
            else:
                ignore_header_line_number = 0

            log_count = len(self.rawdata.readlines())
            self.split_logs_to_sqs(log_count, max_log_count)
            if self.start_number == 0:
                start = ignore_header_line_number
                if (max_log_count >= log_count
                        or not es_loader.SQS_SPLITTED_LOGS_URL):
                    end = log_count
                else:
                    end = max_log_count
            else:
                start = self.start_number - 1
                end = self.end_number
            self.total_log_count = end - start
            for logdata in self.rawdata.readlines()[start:end]:
                yield logdata.strip()

        elif 'json' in self.file_format:
            log_count = 0
            for x in self.extract_logobj_from_json(mode='count'):
                log_count = x
            self.total_log_count = log_count
            self.split_logs_to_sqs(log_count, max_log_count)
            logobjs = self.extract_logobj_from_json(
                'extract', self.start_number, self.end_number, log_count,
                max_log_count)
            for logobj in logobjs:
                yield logobj

    @property
    def startmsg(self):
        startmsg = {'s3_bucket': self.s3bucket, 's3_key': self.s3key,
                    'logtype': self.logtype, 'start_number': self.start_number,
                    'end_number': self.end_number}
        return startmsg


class LogKinesis(LogObj):
    """ Kinesisで受信したCWLのログから表層的に情報を取得する。
    圧縮の有無の判断、ログ種類を判断、フォーマットの判断をして
    最後に、生ファイルを個々のログに分割してリスト型として返す
    入力値となるKinesisのJSONサンプルはこちら
    https://docs.aws.amazon.com/ja_jp/lambda/latest/dg/with-kinesis-example.html
    """
    def __init__(self, record, config):
        super().__init__(config)
        self.config = config
        self.rawdata_dict = self.get_rawdata_dict(record)
        self.loggroup = self.rawdata_dict['logGroup']
        self.logstream = self.rawdata_dict['logStream']
        self.msgformat = 'kinesis'
        self.ignore = self.check_ignore()
        self.__file_format = None

    def get_rawdata_dict(self, record):
        payload = base64.b64decode(record['kinesis']['data'])
        gzipbody = io.BytesIO(payload)
        body = gzip.open(gzipbody, mode='rt').readline()
        body_dict = json.loads(body)
        return body_dict

    def check_ignore(self):
        if 'CONTROL_MESSAGE' in self.rawdata_dict['messageType']:
            return "Kinesis's control_message"
        if 'unknown' in self.logtype:
            # 対応していないlogtypeはunknownになる。その場合は処理をスキップさせる
            return "Unknown log type in kinesis"
        else:
            return False

    @property
    def logtype(self):
        for section in self.config.sections():
            if self.config[section]['loggroup'] in self.loggroup.lower():
                return section
            else:
                try:
                    # CWEでログをCWLに送るとaws sourceが入ってるのでそれで評価
                    meta = self.rawdata_dict['logEvents'][0]['message'][:150]
                except KeyError:
                    meta = ''
                if self.config[section]['loggroup'] in meta.lower():
                    return section
        return 'unknown'

    @property
    def accountid(self):
        return self.rawdata_dict['owner']

    @property
    def region(self):
        text = self.loggroup.lower() + '_' + self.logstream.lower()
        return utils.extract_aws_region_from_text(text)

    @property
    def logdata_list(self):
        for record in self.rawdata_dict['logEvents']:
            # CWLでJSON化してる場合 eg) vpcflowlogs
            if 'extractedFields' in record:
                self.__file_format = 'json'
                yield record
                continue
            if self.config[self.logtype]['file_format'] == 'text':
                yield record['message']
                continue
            record = json.loads(record['message'])
            # CWEにて送られたCWLかどうかの判定 eg) securityhub, guardduty
            cwl_keys = ('source', 'detail', 'resources', 'account', 'time')
            if all(k in record for k in cwl_keys):
                record = record['detail']
                # 1つのJSNにログが複数ある場合 eg) securityhub
                delimiter = self.config[self.logtype]['json_delimiter']
                if delimiter:
                    for each_event in record[delimiter]:
                        yield each_event
                else:
                    yield record
            else:
                yield record

    @property
    def startmsg(self):
        startmsg = ('AccountID: {0}, logGroup: {1}, logStream: {2}'.format(
            self.accountid, self.loggroup, self.logstream))
        return startmsg

    @property
    def file_format(self):
        if self.__file_format:
            return self.__file_format
        else:
            return self.config[self.logtype]['file_format']


class LogParser:
    """ 生ファイルから、ファイルタイプ毎に、タイムスタンプの抜き出し、
    テキストなら名前付き正規化による抽出、エンリッチ(geoipなどの付与)、
    フィールドのECSへの統一、最後にJSON化、する
    """
    def __init__(self, logdata, logtype, logconfig, msgformat=None,
                 logformat=None, header=None, s3bucket=None, s3key=None,
                 loggroup=None, logstream=None, accountid=None, region=None,
                 via_firelens=None, log_pattern_prog=None, sf_module=None,
                 *args, **kwargs):
        self.msgformat = msgformat
        self.logdata = logdata
        self.logtype = logtype
        self.logconfig = logconfig
        self.logformat = logformat
        self.s3bucket = s3bucket
        self.s3key = s3key
        self.loggroup = loggroup
        self.logstream = logstream
        self.accountid = accountid
        self.region = region
        self.log_pattern_prog = log_pattern_prog
        self.header = header
        self.via_firelens = via_firelens
        self.__logdata_dict = self.logdata_to_dict()
        self.is_ignored = self.__logdata_dict.get('is_ignored')
        self.__skip_normalization = self.__logdata_dict.get(
            '__skip_normalization')
        self.sf_module = sf_module

    def logdata_to_dict(self):
        logdata_dict = {}

        firelens_meta_dict = {}
        if self.via_firelens:
            (self.logdata, firelens_meta_dict) = (
                self.get_log_and_meta_from_firelens())
            if firelens_meta_dict['container_source'] == 'stderr':
                ignore_container_stderr = self.logconfig.getboolean(
                    'ignore_container_stderr')
                if ignore_container_stderr:
                    return {'is_ignored': True}
                else:
                    d = {'__skip_normalization': True,
                         'error': {'message': self.logdata}}
                    firelens_meta_dict.update(d)
                    return firelens_meta_dict
            if self.logformat in 'json':
                self.logdata = json.loads(self.logdata)

        if 'kinesis' in self.msgformat and 'extractedFields' in self.logdata:
            # CWLでJSON化してる場合
            logdata_dict = self.logdata['extractedFields']
        elif self.logformat in 'csv':
            logdata_dict = dict(zip(self.header.split(), self.logdata.split()))
            utils.conv_key(logdata_dict)
        elif self.logformat in 'json':
            logdata_dict = self.logdata
        elif self.logformat in 'text':
            try:
                m = self.log_pattern_prog.match(self.logdata)
            except AttributeError:
                msg = 'No log_pattern. You need to define it in user.ini'
                logger.exception(msg)
                raise AttributeError(msg) from None
            if m:
                logdata_dict = m.groupdict()
            else:
                msg_dict = {
                    'Exception': f'Invalid regex paasttern of {self.logtype}',
                    'rawdata': self.logdata,
                    'regex_pattern': self.log_pattern_prog}
                logger.error(msg_dict)
                raise Exception(repr(msg_dict))

        if self.via_firelens:
            logdata_dict.update(firelens_meta_dict)

        return logdata_dict

    def get_log_and_meta_from_firelens(self):
        obj = json.loads(self.logdata)
        firelens_meta_dict = {}
        # basic firelens field
        firelens_meta_dict['container_id'] = obj.get('container_id')
        firelens_meta_dict['container_name'] = obj.get('container_name')
        firelens_meta_dict['container_source'] = obj.get('source')
        # ecs meta data
        firelens_meta_dict['ecs_cluster'] = obj.get('ecs_cluster')
        firelens_meta_dict['ecs_task_arn'] = obj.get('ecs_task_arn')
        firelens_meta_dict['ecs_task_definition'] = obj.get(
            'ecs_task_definition')
        firelens_meta_dict['ec2_instance_id'] = obj.get('ec2_instance_id')
        # original log
        logdata = obj['log']
        return logdata, firelens_meta_dict

    def check_ignored_log(self, ignore_list):
        is_excluded = False
        if self.logtype in ignore_list:
            is_excluded = utils.match_log_with_exclude_patterns(
                self.__logdata_dict, ignore_list[self.logtype])
        return is_excluded

    def add_basic_field(self):
        basic_dict = {}
        if 'kinesis' in self.msgformat and 'extractedFields' in self.logdata:
            basic_dict['@message'] = self.logdata['message']
        elif self.logformat in 'json':
            basic_dict['@message'] = str(json.dumps(self.logdata))
        else:
            basic_dict['@message'] = str(self.logdata)
        basic_dict['event'] = {'module': self.logtype}
        self.__timestamp = self.get_timestamp()
        basic_dict['@timestamp'] = self.timestamp.isoformat()
        self.__event_ingested = datetime.now(timezone.utc)
        basic_dict['event']['ingested'] = self.event_ingested.isoformat()
        basic_dict['@log_type'] = self.logtype
        if self.logconfig['doc_id'] and not self.__skip_normalization:
            basic_dict['@id'] = self.__logdata_dict[self.logconfig['doc_id']]
        else:
            basic_dict['@id'] = hashlib.md5(
                str(basic_dict['@message']).encode('utf-8')).hexdigest()
        if self.loggroup:
            basic_dict['@log_group'] = self.loggroup
            basic_dict['@log_stream'] = self.logstream
        if self.s3bucket:
            basic_dict['@log_s3bucket'] = self.s3bucket
            basic_dict['@log_s3key'] = self.s3key
        self.__logdata_dict.update(basic_dict)

    def clean_multi_type_field(self):
        clean_multi_type_dict = {}
        multifield_keys = self.logconfig['json_to_text'].split()
        for multifield_key in multifield_keys:
            v = utils.get_value_from_dict(self.__logdata_dict, multifield_key)
            if v:
                # json obj in json obj
                if isinstance(v, int):
                    new_dict = utils.put_value_into_dict(multifield_key, v)
                elif '{' in v:
                    new_dict = utils.put_value_into_dict(
                        multifield_key, repr(v))
                else:
                    new_dict = utils.put_value_into_dict(
                        multifield_key, str(v))
                clean_multi_type_dict = utils.merge_dicts(
                    clean_multi_type_dict, new_dict)
        self.__logdata_dict = utils.merge_dicts(
            self.__logdata_dict, clean_multi_type_dict)

    def transform_to_ecs(self):
        ecs_dict = {'ecs': {'version': self.logconfig['ecs_version']}}
        if self.logconfig['cloud_provider']:
            ecs_dict['cloud'] = {'provider': self.logconfig['cloud_provider']}
        ecs_keys = self.logconfig['ecs'].split()
        for ecs_key in ecs_keys:
            original_keys = self.logconfig[ecs_key]
            v = utils.get_value_from_dict(self.__logdata_dict, original_keys)
            if v:
                new_ecs_dict = utils.put_value_into_dict(ecs_key, v)
                if '.ip' in ecs_key:
                    # IPアドレスの場合は、validation
                    try:
                        ipaddress.ip_address(v)
                    except ValueError:
                        continue
                ecs_dict = utils.merge_dicts(ecs_dict, new_ecs_dict)
        if 'cloud' in ecs_dict:
            # Set AWS Account ID
            if ('account' in ecs_dict['cloud']
                    and 'id' in ecs_dict['cloud']['account']):
                if ecs_dict['cloud']['account']['id'] in ('unknown', ):
                    # for vpcflowlogs
                    ecs_dict['cloud']['account'] = {'id': self.accountid}
            elif self.accountid:
                ecs_dict['cloud']['account'] = {'id': self.accountid}
            else:
                ecs_dict['cloud']['account'] = {'id': 'unknown'}

            # Set AWS Region
            if 'region' in ecs_dict['cloud']:
                pass
            elif self.region:
                ecs_dict['cloud']['region'] = self.region
            else:
                ecs_dict['cloud']['region'] = 'unknown'

        # get info from firelens metadata of Elastic Container Serivce
        if 'ecs_task_arn' in self.__logdata_dict:
            ecs_task_arn_taple = self.__logdata_dict['ecs_task_arn'].split(':')
            ecs_dict['cloud']['account']['id'] = ecs_task_arn_taple[4]
            ecs_dict['cloud']['region'] = ecs_task_arn_taple[3]
            ecs_dict['cloud']['instance'] = {
                'id': self.__logdata_dict['ec2_instance_id']}
            ecs_dict['container'] = {
                'id': self.__logdata_dict['container_id'],
                'name': self.__logdata_dict['container_name']}

        static_ecs_keys = self.logconfig.get('static_ecs')
        if static_ecs_keys:
            for static_ecs_key in static_ecs_keys.split():
                new_ecs_dict = utils.put_value_into_dict(
                    static_ecs_key, self.logconfig[static_ecs_key])
                ecs_dict = utils.merge_dicts(ecs_dict, new_ecs_dict)
        self.__logdata_dict = utils.merge_dicts(self.__logdata_dict, ecs_dict)

    def transform_by_script(self):
        # if overrite index_name, add key(__logdata_dict) to self.
        if self.logconfig['script_ecs']:
            self.__logdata_dict = self.sf_module.transform(self.__logdata_dict)

    def enrich(self, geodb_instance):
        enrich_dict = {}
        # geoip
        geoip_list = self.logconfig['geoip'].split()
        for geoip_ecs in geoip_list:
            try:
                ipaddr = self.__logdata_dict[geoip_ecs]['ip']
            except KeyError:
                continue
            geoip, asn = geodb_instance.check_ipaddress(ipaddr)
            if geoip:
                enrich_dict[geoip_ecs] = {'geo': geoip}
            if geoip and asn:
                enrich_dict[geoip_ecs].update({'as': asn})
            elif asn:
                enrich_dict[geoip_ecs] = {'as': asn}
        self.__logdata_dict = utils.merge_dicts(
            self.__logdata_dict, enrich_dict)

    @property
    def doc_id(self):
        if '__doc_id_suffix' in self.__logdata_dict:
            temp = self.__logdata_dict['__doc_id_suffix']
            del self.__logdata_dict['__doc_id_suffix']
            return '{0}_{1}'.format(self.__logdata_dict['@id'], temp)
        if self.logconfig['doc_id_suffix']:
            suffix = utils.get_value_from_dict(
                self.__logdata_dict, self.logconfig.get('doc_id_suffix'))
            if suffix:
                return '{0}_{1}'.format(self.__logdata_dict['@id'], suffix)
        return self.__logdata_dict['@id']

    def get_timestamp(self):
        if 'timestamp' in self.logconfig and self.logconfig['timestamp']:
            # this is depprecatd code of v1.5.2 and keep for compatibility
            timestamp_list = self.logconfig['timestamp'].split(',')
            self.logconfig['timestamp_key'] = timestamp_list[0]
            if len(timestamp_list) == 2:
                self.logconfig['timestamp_format'] = timestamp_list[1]
            # フォーマットの指定がなければISO9601と仮定。
        if self.logconfig['timestamp_key'] and not self.__skip_normalization:
            # new code from ver 1.6.0
            timestamp_key = self.logconfig['timestamp_key']
            timestamp_format = self.logconfig['timestamp_format']
            timestamp_tz = float(self.logconfig['timestamp_tz'])
            TZ = timezone(timedelta(hours=timestamp_tz))
            # 末尾がZはPythonでは対応していないのでカットしてTZを付与
            try:
                timestr = self.__logdata_dict[timestamp_key].replace(
                    'Z', '+00:00')
            except AttributeError:
                # int such as epoch
                timestr = self.__logdata_dict[timestamp_key]
            if self.logconfig.getboolean('timestamp_nano'):
                m = utils.RE_WITH_NANOSECONDS.match(timestr)
                if m and m.group(3):
                    microsec = m.group(2)[:9].ljust(6, '0')
                    timestr = m.group(1) + microsec + m.group(3)
            if 'epoch' in timestamp_format:
                epoch = float(timestr)
                if epoch > 1000000000000:
                    # milli epoch
                    epoch_seconds = epoch / 1000
                    dt = datetime.fromtimestamp(epoch_seconds, tz=TZ)
                else:
                    # normal epoch
                    dt = datetime.fromtimestamp(epoch, tz=TZ)
            elif 'syslog' in timestamp_format:
                # timezoneを考慮して、12時間を早めた現在時刻を基準とする
                now = datetime.now(timezone.utc) + utils.TD_OFFSET12
                m = utils.RE_SYSLOG_FORMAT.match(timestr)
                try:
                    # コンマ以下の秒があったら
                    microsec = int(m.group(7).ljust(6, '0'))
                except AttributeError:
                    microsec = 0
                try:
                    dt = datetime(
                        year=now.year, month=utils.MONTH_TO_INT[m.group(1)],
                        day=int(m.group(2)), hour=int(m.group(3)),
                        minute=int(m.group(4)), second=int(m.group(5)),
                        microsecond=microsec, tzinfo=TZ)
                except ValueError:
                    # うるう年対策
                    last_year = now.year - 1
                    dt = datetime(
                        year=last_year, month=utils.MONTH_TO_INT[m.group(1)],
                        day=int(m.group(2)), hour=int(m.group(3)),
                        minute=int(m.group(4)), second=int(m.group(5)),
                        microsecond=microsec, tzinfo=TZ)
                if dt > now:
                    # syslog timestamp が未来。マイナス1年の補正が必要
                    # know_issue: 1年以上古いログの補正はできない
                    last_year = now.year - 1
                    dt = dt.replace(year=last_year)
                else:
                    # syslog timestamp が過去であり適切。処理なし
                    pass
            elif 'iso8601' in timestamp_format:
                try:
                    dt = datetime.fromisoformat(timestr)
                except ValueError:
                    msg = (f'You set {timestamp_key} field as ISO8601 format. '
                           f'Timestamp string is {timestr} and NOT ISO8601. ')
                    logger.exception(msg)
                    raise ValueError(msg) from None
                if not dt.tzinfo:
                    dt = dt.replace(tzinfo=TZ)
            elif timestamp_format:
                try:
                    dt = datetime.strptime(timestr, timestamp_format)
                except ValueError:
                    msg = f'timestamp key {timestamp_key} is wrong'
                    logger.exception(msg)
                    raise ValueError(msg) from None
                if not dt.tzinfo:
                    dt = dt.replace(tzinfo=TZ)
            else:
                msg = f'There is no timestamp format for {self.logtype}'
                logger.error(msg)
                raise ValueError(msg)
        else:
            dt = datetime.now(timezone.utc)
        return dt

    @property
    def timestamp(self):
        return self.__timestamp

    @property
    def event_ingested(self):
        return self.__event_ingested

    @property
    def indexname(self):
        if '__index_name' in self.__logdata_dict:
            indexname = self.__logdata_dict['__index_name']
            del self.__logdata_dict['__index_name']
        else:
            indexname = self.logconfig['index_name']
        if 'auto' in self.logconfig['index_rotation']:
            return indexname
        if 'event_ingested' in self.logconfig['index_time']:
            index_dt = self.event_ingested
        else:
            index_dt = self.timestamp
        if self.logconfig['index_tz']:
            TZ = timezone(timedelta(hours=float(self.logconfig['index_tz'])))
            index_dt = index_dt.astimezone(TZ)
        if 'daily' in self.logconfig['index_rotation']:
            return indexname + index_dt.strftime('-%Y-%m-%d')
        elif 'weekly' in self.logconfig['index_rotation']:
            return indexname + index_dt.strftime('-%Y-w%W')
        elif 'monthly' in self.logconfig['index_rotation']:
            return indexname + index_dt.strftime('-%Y-%m')
        else:
            return indexname + index_dt.strftime('-%Y')

    def del_none(self, d):
        """値のないキーを削除する。削除しないとESへのLoad時にエラーとなる """
        for key, value in list(d.items()):
            if isinstance(value, dict):
                self.del_none(value)
            if isinstance(value, dict) and len(value) == 0:
                del d[key]
            elif isinstance(value, list) and len(value) == 0:
                del d[key]
            elif isinstance(value, str) and (value in ('', '-', 'null', '[]')):
                del d[key]
        return d

    @property
    def json(self):
        # 内部で管理用のフィールドを削除
        try:
            del self.__logdata_dict['__skip_normalization']
        except Exception:
            pass
        self.__logdata_dict = self.del_none(self.__logdata_dict)
        return json.dumps(self.__logdata_dict)


###############################################################################
# DEPRECATED function. Moved to siem.utils
###############################################################################
def get_value_from_dict(dct, xkeys_list):
    """Deprecated.
    入れ子になった辞書に対して、dotを含んだkeyで値を
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
    """Deprecated.
    dictのkeyにドットが含まれている場合に入れ子になったdictを作成し、値としてvを入れる.
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
        new_dict = utils.put_value_into_dict(key_str, 'DROPPED')
    return new_dict


def conv_key(obj):
    """Deprecated.
    dictのkeyに-が入ってたら_に置換する
    """
    if isinstance(obj, dict):
        for org_key in list(obj.keys()):
            new_key = org_key
            if '-' in org_key:
                new_key = org_key.translate({ord('-'): ord('_')})
                obj[new_key] = obj.pop(org_key)
            utils.conv_key(obj[new_key])
    elif isinstance(obj, list):
        for val in obj:
            utils.conv_key(val)
    else:
        pass


def merge(a, b, path=None):
    """Deprecated.
    merges b into a
    Moved to siem.utils.merge_dicts.
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
    """Deprecated.
    ログと、log_patterns を比較させる
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
