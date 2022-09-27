# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.8.0c'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import bz2
import gzip
import io
import zipfile

from aws_lambda_powertools import Logger

from siem import utils

logger = Logger(child=True)


class FileFormatBase(object):
    def __init__(self, rawdata=None, logconfig=None, logtype=None):
        self._rawdata = rawdata
        self.logconfig = logconfig
        self.logtype = logtype
        self._filename = None

    @property
    def filename(self):
        return self._filename

    @filename.setter
    def filename(self, filename):
        self._filename = filename

    @property
    def rawdata(self):
        if self._rawdata:
            self._rawdata.seek(0)
            return self._rawdata
        elif self.filename:
            # for just testing.
            with open(self.filename, 'rb') as f:
                rawbody = io.BytesIO(f.read())
            mime_type = utils.get_mime_type(rawbody.read(16))
            rawbody.seek(0)
            if mime_type == 'gzip':
                body = gzip.open(
                    rawbody, mode='rt', encoding='utf8', errors='ignore')
            elif mime_type == 'text':
                body = io.TextIOWrapper(
                    rawbody, encoding='utf8', errors='ignore')
            elif mime_type == 'zip':
                z = zipfile.ZipFile(rawbody)
                body = open(z.namelist()[0], encoding='utf8', errors='ignore')
            elif mime_type == 'bzip2':
                body = bz2.open(
                    rawbody, mode='rt', encoding='utf8', errors='ignore')
            else:
                raise Exception('unknown file format')
            return body

    @rawdata.setter
    def rawdata(self, rawdata):
        self._rawdata = rawdata

    @property
    def log_count(self):
        return 0

    @property
    def ignore_header_line_number(self):
        return 0

    def extract_log(self, start=0, end=0, logmeta={}):
        logger.critical('Impossible to extract unknown log format of '
                        f'{self.logtype}. You should configure "file_format" '
                        'in user.ini')
        return

    def convert_lograw_to_dict(self, lograw, logconfig=None):
        return lograw
