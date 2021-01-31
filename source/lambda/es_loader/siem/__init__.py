# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import bz2
from datetime import datetime, timedelta, timezone
from functools import cached_property
import gzip
import hashlib
import io
import ipaddress
import json
import re
import urllib.parse
import zipfile

from aws_lambda_powertools import Logger

from siem import utils

__version__ = '2.2.0-beta.6'

logger = Logger(child=True)


class LogS3:
    """取得した一連のログファイルから表層的な情報を取得し、個々のログを返す.

    圧縮の有無の判断、ログ種類を判断、フォーマットの判断をして
    最後に、生ファイルを個々のログに分割してリスト型として返す
    """
    def __init__(self, record, logtype, logconfig, s3_client, sqs_queue):
        self.record = record
        self.logtype = logtype
        self.logconfig = logconfig
        self.s3_client = s3_client
        self.sqs_queue = sqs_queue

        self.loggroup = None
        self.logstream = None
        self.s3bucket = self.record['s3']['bucket']['name']
        self.s3key = self.record['s3']['object']['key']

        logger.info(self.startmsg())
        if self.is_ignored:
            return None
        self.via_cwl = self.logconfig['via_cwl']
        self.via_firelens = self.logconfig['via_firelens']
        self.file_format = self.logconfig['file_format']
        self.max_log_count = self.logconfig['max_log_count']

        self.__rawdata = self.extract_rawdata_from_s3obj()

        if self.via_cwl:
            self.loggroup, self.logstream, self.cwl_accountid = (
                self.extract_header_from_cwl(self.__rawdata))
            self.__rawdata.seek(0)
            self.__rawdata = self.extract_messages_from_cwl(self.__rawdata)

    def __iter__(self):
        if self.is_ignored:
            return
        if self.log_count >= self.max_log_count:
            if self.sqs_queue:
                metadata = self.split_logs(self.log_count, self.max_log_count)
                sent_count = self.send_meta_to_sqs(metadata)
                self.is_ignored = True
                self.ignored_reason = (f'Log file was split into {sent_count}'
                                       f' pieces and sent to SQS.')
                return
        yield from self.logdata_generator()

    ###########################################################################
    # Property
    ###########################################################################
    @cached_property
    def is_ignored(self):
        if 'unknown' in self.logtype:
            # 対応していないlogtypeはunknownになる。その場合は処理をスキップさせる
            self.ignored_reason = f'Unknown log type in S3 key, {self.s3key}'
            return True
        re_s3_key_ignored = self.logconfig['s3_key_ignored']
        if re_s3_key_ignored:
            m = re_s3_key_ignored.search(self.s3key)
            if m:
                self.ignored_reason = (fr'"s3_key_ignored" {re_s3_key_ignored}'
                                       fr' matched with {self.s3key}')
                return True
        return False

    @cached_property
    def log_count(self):
        if self.end_number == 0:
            if self.file_format in ('text', 'csv') or self.via_firelens:
                log_count = len(self.rawdata.readlines())
            elif 'json' in self.file_format:
                log_count = 0
                for x in self.extract_logobj_from_json(mode='count'):
                    log_count = x
            else:
                log_count = 0
            if log_count == 0:
                self.is_ignored = True
                self.ignored_reason = (
                    'there are not any valid logs in S3 object')
            return log_count
        else:
            return (self.end_number - self.start_number)

    @property
    def rawdata(self):
        self.__rawdata.seek(0)
        return self.__rawdata

    @cached_property
    def csv_header(self):
        if 'csv' in self.file_format:
            return self.rawdata.readlines()[0].strip()
        else:
            return None

    @cached_property
    def accountid(self):
        if hasattr(self, 'cwl_accountid') and self.cwl_accountid is not None:
            return self.cwl_accountid
        elif hasattr(self, 'cwe_accountid') and self.cwe_accountid is not None:
            return self.cwe_accountid
        s3key_accountid = utils.extract_aws_account_from_text(self.s3key)
        if s3key_accountid:
            return s3key_accountid
        else:
            return None

    @cached_property
    def region(self):
        if hasattr(self, 'cwe_region') and self.cwe_region is not None:
            return self.cwe_region
        s3key_region = utils.extract_aws_region_from_text(self.s3key)
        if s3key_region:
            return s3key_region
        else:
            return None

    @cached_property
    def start_number(self):
        try:
            return int(self.record['siem']['start_number'])
        except KeyError:
            return 0

    @cached_property
    def end_number(self):
        try:
            return int(self.record['siem']['end_number'])
        except KeyError:
            return 0

    ###########################################################################
    # Method/Function
    ###########################################################################
    def startmsg(self):
        startmsg = {'msg': 'Invoked es-loader', 's3_bucket': self.s3bucket,
                    's3_key': self.s3key, 'logtype': self.logtype,
                    'start_number': self.start_number,
                    'end_number': self.end_number}
        return startmsg

    def logdata_generator(self):
        if 'text' in self.file_format:
            ignore_header_line_number = self.logconfig[
                'text_header_line_number']
        elif 'csv' in self.file_format:
            ignore_header_line_number = 1
        else:
            ignore_header_line_number = 0
        if self.start_number <= ignore_header_line_number:
            start = ignore_header_line_number
            if self.max_log_count >= self.log_count:
                end = self.log_count
            else:
                end = self.max_log_count
        else:
            start = self.start_number - 1
            end = self.end_number
        self.total_log_count = end - start

        if self.file_format in ('text', 'csv') or self.via_firelens:
            for logdata in self.rawdata.readlines()[start:end]:
                yield logdata.strip()
        elif 'json' in self.file_format:
            logobjs = self.extract_logobj_from_json('extract', start, end)
            for logobj in logobjs:
                yield logobj
        else:
            raise Exception

    def extract_header_from_cwl(self, rawdata):
        index = 0
        body = rawdata
        decoder = json.JSONDecoder()
        while True:
            obj, offset = decoder.raw_decode(body.read())
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
        rawlog = rawlog_io_obj.read()
        size = len(rawlog)
        index = 0
        newlog_io_obj = io.StringIO()
        while size > index:
            obj, index = decoder.raw_decode(rawlog, index)
            if 'CONTROL_MESSAGE' in obj['messageType']:
                continue
            for log in obj['logEvents']:
                newlog_io_obj.write(log['message'] + "\n")
        newlog_io_obj.seek(0)
        return newlog_io_obj

    def extract_rawdata_from_s3obj(self):
        try:
            safe_s3_key = urllib.parse.unquote_plus(self.s3key)
            obj = self.s3_client.get_object(
                Bucket=self.s3bucket, Key=safe_s3_key)
        except Exception:
            msg = f'Failed to download S3 object from {self.s3key}'
            logger.exception(msg)
            raise Exception(msg) from None
        # if obj['ResponseMetadata']['HTTPHeaders']['content-length'] == '0':
        #    raise Exception('No Contents in s3 object')
        rawbody = io.BytesIO(obj['Body'].read())
        mime_type = utils.get_mime_type(rawbody.read(16))
        rawbody.seek(0)
        if mime_type == 'gzip':
            body = gzip.open(rawbody, mode='rt', encoding='utf8',
                             errors='ignore')
        elif mime_type == 'text':
            body = io.TextIOWrapper(rawbody, encoding='utf8', errors='ignore')
        elif mime_type == 'zip':
            z = zipfile.ZipFile(rawbody)
            body = open(z.namelist()[0], encoding='utf8', errors='ignore')
        elif mime_type == 'bzip2':
            body = bz2.open(rawbody, mode='rt', encoding='utf8',
                            errors='ignore')
        else:
            logger.error('unknown file format')
            raise Exception('unknown file format')
        return body

    def extract_logobj_from_json(self, mode='count', start=0, end=0):
        decoder = json.JSONDecoder()
        delimiter = self.logconfig['json_delimiter']
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

    def check_cwe_and_strip_header(self, dict_obj):
        if "detail-type" in dict_obj and "resources" in dict_obj:
            self.cwe_accountid = dict_obj['account']
            self.cwe_region = dict_obj['region']
            # source = dict_obj['source'] # eg) aws.securityhub
            # time = dict_obj['time'] #@ingested
            return dict_obj['detail']
        else:
            return dict_obj

    def split_logs(self, log_count, max_log_count):
        q, mod = divmod(log_count, max_log_count)
        if mod != 0:
            q = q + 1
        splite_logs_list = []
        for x in range(q):
            if x == 0:
                start = 1
            else:
                start = x * max_log_count + 1
            end = (x + 1) * max_log_count
            if (x == q - 1) and (mod != 0):
                end = x * max_log_count + mod
            splite_logs_list.append((start, end))
        return splite_logs_list

    def send_meta_to_sqs(self, metadata):
        logger.debug({'split_logs': f's3://{self.s3bucket}/{self.s3key}',
                      'max_log_count': self.max_log_count,
                      'log_count': self.log_count})
        entries = []
        last_num = len(metadata)
        for i, (start, end) in enumerate(metadata):
            queue_body = {
                "siem": {"start_number": start, "end_number": end},
                "s3": {"bucket": {"name": self.s3bucket},
                       "object": {"key": self.s3key}}}
            message_body = json.dumps(queue_body)
            entries.append({'Id': f'num_{start}', 'MessageBody': message_body})
            if (len(entries) == 10) or (i == last_num - 1):
                response = self.sqs_queue.send_messages(Entries=entries)
                if response['ResponseMetadata']['HTTPStatusCode'] != 200:
                    logger.error(json.dumps(response))
                    raise Exception(json.dumps(response))
                entries = []
        return last_num


class LogParser:
    """LogParser class.

    生ファイルから、ファイルタイプ毎に、タイムスタンプの抜き出し、
    テキストなら名前付き正規化による抽出、エンリッチ(geoipなどの付与)、
    フィールドのECSへの統一、最後にJSON化、する
    """
    def __init__(self, logfile, logconfig, sf_module, geodb_instance,
                 exclude_log_patterns):
        self.logfile = logfile
        self.logconfig = logconfig
        self.sf_module = sf_module
        self.geodb_instance = geodb_instance
        self.exclude_log_patterns = exclude_log_patterns

        self.logtype = logfile.logtype
        self.s3key = logfile.s3key
        self.s3bucket = logfile.s3bucket
        self.logformat = logfile.file_format
        self.header = logfile.csv_header
        self.accountid = logfile.accountid
        self.region = logfile.region
        self.loggroup = logfile.loggroup
        self.logstream = logfile.logstream
        self.via_firelens = logfile.via_firelens

        self.timestamp_tz = timezone(
            timedelta(hours=float(self.logconfig['timestamp_tz'])))
        if self.logconfig['index_tz']:
            self.index_tz = timezone(
                timedelta(hours=float(self.logconfig['index_tz'])))
        self.has_nanotime = self.logconfig['timestamp_nano']

    def __call__(self, logdata):
        self.logdata = logdata
        self.__logdata_dict = self.logdata_to_dict(logdata)
        if self.is_ignored:
            return
        self.__event_ingested = datetime.now(timezone.utc)
        self.__skip_normalization = self.set_skip_normalization()
        self.__timestamp = self.get_timestamp()

        # idなどの共通的なフィールドを追加する
        self.add_basic_field()
        # logger.debug({'doc_id': self.doc_id})
        # 同じフィールド名で複数タイプがあるとESにロードするとエラーになるので
        # 該当フィールドだけテキスト化する
        self.clean_multi_type_field()
        # フィールドをECSにマッピングして正規化する
        self.transform_to_ecs()
        # 一部のフィールドを修正する
        self.transform_by_script()
        # ログにgeoipなどの情報をエンリッチ
        self.enrich()

    ###########################################################################
    # Property
    ###########################################################################
    @property
    def is_ignored(self):
        if self.__logdata_dict.get('is_ignored'):
            self.ignored_reason = self.__logdata_dict.get('ignored_reason')
            return True
        if self.logtype in self.exclude_log_patterns:
            is_excluded, ex_pattern = utils.match_log_with_exclude_patterns(
                self.__logdata_dict, self.exclude_log_patterns[self.logtype])
            if is_excluded:
                self.ignored_reason = (
                    f'matched {ex_pattern} with exclude_log_patterns')
                return True
        return False

    @property
    def timestamp(self):
        return self.__timestamp

    @property
    def event_ingested(self):
        return self.__event_ingested

    @property
    def doc_id(self):
        if '__doc_id_suffix' in self.__logdata_dict:
            # this field is added by sf_ script
            temp = self.__logdata_dict['__doc_id_suffix']
            del self.__logdata_dict['__doc_id_suffix']
            return '{0}_{1}'.format(self.__logdata_dict['@id'], temp)
        if self.logconfig['doc_id_suffix']:
            suffix = utils.value_from_nesteddict_by_dottedkey(
                self.__logdata_dict, self.logconfig['doc_id_suffix'])
            if suffix:
                return '{0}_{1}'.format(self.__logdata_dict['@id'], suffix)
        return self.__logdata_dict['@id']

    @property
    def indexname(self):
        if '__index_name' in self.__logdata_dict:
            # this field is added by sf_ script
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
            index_dt = index_dt.astimezone(self.index_tz)
        if 'daily' in self.logconfig['index_rotation']:
            return indexname + index_dt.strftime('-%Y-%m-%d')
        elif 'weekly' in self.logconfig['index_rotation']:
            return indexname + index_dt.strftime('-%Y-w%W')
        elif 'monthly' in self.logconfig['index_rotation']:
            return indexname + index_dt.strftime('-%Y-%m')
        else:
            return indexname + index_dt.strftime('-%Y')

    @property
    def json(self):
        # 内部で管理用のフィールドを削除
        self.__logdata_dict = self.del_none(self.__logdata_dict)
        return json.dumps(self.__logdata_dict)

    ###########################################################################
    # Method/Function - Main
    ###########################################################################
    def logdata_to_dict(self, logdata):
        logdata_dict = {}
        firelens_meta_dict = {}
        if self.via_firelens:
            logdata, firelens_meta_dict = self.get_log_and_meta_from_firelens()
            self.logdata = logdata
            logdata, is_valid_log = self.validate_logdata_in_firelens(
                logdata, firelens_meta_dict)
            if not is_valid_log:
                return logdata
        if self.logformat in 'csv':
            logdata_dict = dict(zip(self.header.split(), logdata.split()))
            logdata_dict = utils.convert_keyname_to_safe_field(logdata_dict)
        elif self.logformat in 'json':
            logdata_dict = logdata
        elif self.logformat in 'text':
            logdata_dict = self.text_logdata_to_dict(logdata)
        if self.via_firelens:
            logdata_dict.update(firelens_meta_dict)
        return logdata_dict

    def add_basic_field(self):
        basic_dict = {}
        if self.logformat in 'json':
            basic_dict['@message'] = str(json.dumps(self.logdata))
        else:
            basic_dict['@message'] = str(self.logdata)
        basic_dict['event'] = {'module': self.logtype}
        basic_dict['@timestamp'] = self.timestamp.isoformat()
        basic_dict['event']['ingested'] = self.event_ingested.isoformat()
        basic_dict['@log_type'] = self.logtype
        if self.__skip_normalization:
            unique_text = "{0}{1}".format(basic_dict['@message'], self.s3key)
            basic_dict['@id'] = hashlib.md5(
                unique_text.encode('utf-8')).hexdigest()
        elif self.logconfig['doc_id']:
            basic_dict['@id'] = self.__logdata_dict[self.logconfig['doc_id']]
        else:
            basic_dict['@id'] = hashlib.md5(
                str(basic_dict['@message']).encode('utf-8')).hexdigest()
        if self.loggroup:
            basic_dict['@log_group'] = self.loggroup
            basic_dict['@log_stream'] = self.logstream
        basic_dict['@log_s3bucket'] = self.s3bucket
        basic_dict['@log_s3key'] = self.s3key
        self.__logdata_dict.update(basic_dict)

    def clean_multi_type_field(self):
        clean_multi_type_dict = {}
        multifield_keys = self.logconfig['json_to_text'].split()
        for multifield_key in multifield_keys:
            v = utils.value_from_nesteddict_by_dottedkey(
                self.__logdata_dict, multifield_key)
            if v:
                # json obj in json obj
                if isinstance(v, int):
                    new_dict = utils.put_value_into_nesteddict(
                        multifield_key, v)
                elif '{' in v:
                    new_dict = utils.put_value_into_nesteddict(
                        multifield_key, repr(v))
                else:
                    new_dict = utils.put_value_into_nesteddict(
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
            v = utils.value_from_nesteddict_by_dottedkeylist(
                self.__logdata_dict, original_keys)
            if v:
                new_ecs_dict = utils.put_value_into_nesteddict(ecs_key, v)
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
            if 'ec2_instance_id' in self.__logdata_dict:
                ecs_dict['cloud']['instance'] = {
                    'id': self.__logdata_dict['ec2_instance_id']}
            ecs_dict['container'] = {
                'id': self.__logdata_dict['container_id'],
                'name': self.__logdata_dict['container_name']}

        static_ecs_keys = self.logconfig['static_ecs']
        if static_ecs_keys:
            for static_ecs_key in static_ecs_keys.split():
                new_ecs_dict = utils.put_value_into_nesteddict(
                    static_ecs_key, self.logconfig[static_ecs_key])
                ecs_dict = utils.merge_dicts(ecs_dict, new_ecs_dict)
        self.__logdata_dict = utils.merge_dicts(self.__logdata_dict, ecs_dict)

    def transform_by_script(self):
        if self.logconfig['script_ecs']:
            self.__logdata_dict = self.sf_module.transform(self.__logdata_dict)

    def enrich(self):
        enrich_dict = {}
        # geoip
        geoip_list = self.logconfig['geoip'].split()
        for geoip_ecs in geoip_list:
            try:
                ipaddr = self.__logdata_dict[geoip_ecs]['ip']
            except KeyError:
                continue
            geoip, asn = self.geodb_instance.check_ipaddress(ipaddr)
            if geoip:
                enrich_dict[geoip_ecs] = {'geo': geoip}
            if geoip and asn:
                enrich_dict[geoip_ecs].update({'as': asn})
            elif asn:
                enrich_dict[geoip_ecs] = {'as': asn}
        self.__logdata_dict = utils.merge_dicts(
            self.__logdata_dict, enrich_dict)

    ###########################################################################
    # Method/Function - Support
    ###########################################################################
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
        ec2_instance_id = obj.get('ec2_instance_id', False)
        if ec2_instance_id:
            firelens_meta_dict['ec2_instance_id'] = ec2_instance_id
        # original log
        logdata = obj['log']
        return logdata, firelens_meta_dict

    def validate_logdata_in_firelens(self, logdata, firelens_meta_dict):
        if firelens_meta_dict['container_source'] == 'stderr':
            ignore_container_stderr_bool = (
                self.logconfig['ignore_container_stderr'])
            if ignore_container_stderr_bool:
                reason = "log is container's stderr"
                return({'is_ignored': True, 'ignored_reason': reason}, False)
            else:
                d = {'__skip_normalization': True,
                     'error': {'message': logdata}}
                firelens_meta_dict.update(d)
                return(firelens_meta_dict, False)
        if self.logformat in 'json':
            try:
                logdata = json.loads(logdata)
            except json.JSONDecodeError:
                error_message = 'Invalid file format found during parsing'
                d = {'__skip_normalization': True,
                     'error': {'message': error_message}}
                firelens_meta_dict.update(d)
                logger.warn(f'{error_message} {self.s3key}')
                return(firelens_meta_dict, False)
        return(logdata, True)

    def text_logdata_to_dict(self, logdata):
        re_log_pattern_prog = self.logconfig['log_pattern']
        try:
            re_log_pattern_prog = self.logconfig['log_pattern']
            m = re_log_pattern_prog.match(logdata)
        except AttributeError:
            msg = 'No log_pattern. You need to define it in user.ini'
            logger.exception(msg)
            raise AttributeError(msg) from None
        if m:
            logdata_dict = m.groupdict()
        else:
            msg_dict = {
                'Exception': f'Invalid regex paasttern of {self.logtype}',
                'rawdata': logdata, 'regex_pattern': re_log_pattern_prog}
            logger.error(msg_dict)
            raise Exception(repr(msg_dict))
        return logdata_dict

    def set_skip_normalization(self):
        if self.__logdata_dict.get('__skip_normalization'):
            del self.__logdata_dict['__skip_normalization']
            return True
        return False

    def get_timestamp(self):
        if self.logconfig['timestamp_key'] and not self.__skip_normalization:
            timestr = utils.get_timestr_from_logdata_dict(
                self.__logdata_dict, self.logconfig['timestamp_key'],
                self.has_nanotime)
            dt = utils.convert_timestr_to_datetime(
                timestr, self.logconfig['timestamp_key'],
                self.logconfig['timestamp_format'], self.timestamp_tz)
            if not dt:
                msg = f'there is no timestamp format for {self.logtype}'
                logger.error(msg)
                raise ValueError(msg)
        else:
            dt = datetime.now(timezone.utc)
        return dt

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


###############################################################################
# DEPRECATED function. Moved to siem.utils
###############################################################################
def get_value_from_dict(dct, xkeys_list):
    """Deprecated. moved to utils.value_from_nesteddict_by_dottedkeylist.

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

    moved to utils.put_value_into_nesteddict
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
        new_dict = put_value_into_dict(key_str, 'DROPPED')
    return new_dict


def conv_key(obj):
    """Deprecated.

    moved to utils.convert_key_to_safe_field
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
