# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.8.0c'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import json
import re

from aws_lambda_powertools import Logger

from siem import FileFormatBase

logger = Logger(child=True)


class FileFormatJson(FileFormatBase):
    def __init__(self, rawdata=None, logconfig=None, logtype=None):
        super().__init__(rawdata, logconfig, logtype)
        self.json_delimiter = logconfig['json_delimiter']

    @property
    def log_count(self):
        decoder = json.JSONDecoder()
        delimiter = self.json_delimiter
        count = 0
        # For ndjson
        for line in self.rawdata.readlines():
            # for Firehose's json (multiple jsons in 1 line)
            size = len(line)
            index = 0
            while index < size:
                raw_event, offset = decoder.raw_decode(line, index)
                raw_event, _ = self._check_cwe_and_strip_header(raw_event)
                if delimiter and (delimiter in raw_event):
                    # multiple evets in 1 json
                    for record in raw_event[delimiter]:
                        count += 1
                elif not delimiter:
                    count += 1
                search = json.decoder.WHITESPACE.search(line, offset)
                if search is None:
                    break
                index = search.end()
        return count

    def extract_log(self, start, end, logmeta={}):
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
                raw_event, logmeta = self._check_cwe_and_strip_header(
                    raw_event, logmeta, need_meta=True)
                if delimiter and (delimiter in raw_event):
                    # multiple evets in 1 json
                    for record in raw_event[delimiter]:
                        count += 1
                        if start <= count <= end:
                            yield (json.dumps(record), record, logmeta)
                        elif count > end:
                            break
                elif not delimiter:
                    count += 1
                    if start <= count <= end:
                        yield (json.dumps(raw_event), raw_event, logmeta)
                    elif count > end:
                        break
                search = json.decoder.WHITESPACE.search(line, offset)
                if search is None:
                    break
                index = search.end()

    def convert_lograw_to_dict(self, lograw, logconfig=None):
        try:
            logdict = json.loads(lograw)
            return logdict
        except json.decoder.JSONDecodeError as e:
            # this is probablly CWL log and trauncated by original log sender
            # such as opensearch audit log
            err = e
            if r'Invalid \escape' in str(e):
                try:
                    lograw = re.sub(r'([^\\])\\x', r'\1\\\\x', lograw)
                    logdict = json.loads(lograw, strict=False)
                    return logdict
                except json.decoder.JSONDecodeError as e:
                    err = e
            logger.warning('This log will be loaded, '
                           'but not parsed because of invalid json')
            logdict = {'__skip_normalization': True,
                       '__error_message': f'invalid json file: {str(err)}'}
            return logdict

    def _check_cwe_and_strip_header(
            self, dict_obj, logmeta={}, need_meta=False):
        if "detail-type" in dict_obj and "resources" in dict_obj:
            if need_meta:
                logmeta = {'cwe_id': dict_obj['id'],
                           'cwe_source': dict_obj['source'],
                           'cwe_accountid': dict_obj['account'],
                           'cwe_region': dict_obj['region'],
                           'cwe_timestamp': dict_obj['time']}
            # source = dict_obj['source'] # eg) aws.securityhub
            # time = dict_obj['time'] #@ingested
            return dict_obj['detail'], logmeta
        else:
            return dict_obj, logmeta
