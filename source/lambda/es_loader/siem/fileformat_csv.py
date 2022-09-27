# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.8.0c'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import csv
from functools import cached_property

from aws_lambda_powertools import Logger

from siem import FileFormatBase

logger = Logger(child=True)


class FileFormatCsv(FileFormatBase):
    def __init__(self, rawdata=None, logconfig=None, logtype=None):
        super().__init__(rawdata, logconfig, logtype)
        self.csv_delimiter = logconfig['csv_delimiter']

    @cached_property
    def log_count(self):
        header_num = self.ignore_header_line_number
        # _line_count = len(self.rawdata.readlines())
        _line_count = sum(1 for line in self.rawdata) - header_num
        if self.csv_delimiter:
            self.rawdata.seek(0)
            spamreader = csv.reader(self.rawdata, delimiter=self.csv_delimiter)
            _row_count = sum(1 for row in spamreader) - header_num
        else:
            self.is_multiline = False
            return _line_count
        if _line_count == _row_count:
            self.is_multiline = False
            return _line_count
        else:
            self.is_multiline = True
            return _row_count

    @property
    def ignore_header_line_number(self):
        # to exclude CSV Header
        return 1

    @cached_property
    def _csv_header(self):
        if self.csv_delimiter:
            spamreader = csv.reader(self.rawdata, delimiter=self.csv_delimiter)
            for x in spamreader:
                header = x
                break
        else:
            header = self.rawdata.readlines()[0].strip().split()
        header = [field.replace('-', '_') for field in header]
        return header

    def extract_log(self, start, end, logmeta={}):
        start_index = start - 1
        end_index = end
        if self.csv_delimiter:
            try:
                is_multiline = self.is_multiline
            except AttributeError:
                _line_count = sum(1 for line in self.rawdata)
                self.rawdata.seek(0)
                spamreader = csv.reader(
                    self.rawdata, delimiter=self.csv_delimiter)
                _row_count = sum(1 for row in spamreader)
                self.rawdata.seek(0)
                if _line_count == _row_count:
                    is_multiline = False
                else:
                    is_multiline = True

        if self.csv_delimiter and (is_multiline is False):
            for logdata in self.rawdata.readlines()[start_index:end_index]:
                lograw = logdata.strip()
                lograw_tuple = None
                for x in csv.reader([lograw], delimiter=self.csv_delimiter):
                    lograw_tuple = x
                logdict = dict(zip(self._csv_header, lograw_tuple))
                yield (lograw, logdict, logmeta)
        elif self.csv_delimiter and (is_multiline is True):
            if start <= 2:
                start = 1
            reader = csv.DictReader(self.rawdata, delimiter=self.csv_delimiter)
            row_count = 1
            for row in reader:
                if start <= row_count <= end:
                    # pseudo lorwar
                    lograw = ','.join([f'"{v}"' for v in row.values()])
                    yield (lograw, row, logmeta)
                if row_count >= end:
                    break
                row_count += 1
        else:
            for logdata in self.rawdata.readlines()[start_index:end_index]:
                lograw = logdata.strip()
                logdict = dict(zip(self._csv_header, lograw.split()))
                yield (lograw, logdict, logmeta)

    def convert_lograw_to_dict(self, lograw, logconfig=None):
        if self.csv_delimiter:
            for x in csv.reader([lograw], delimiter=self.csv_delimiter):
                lograw_tuple = x
        else:
            lograw_tuple = lograw.split()
        logdict = dict(zip(self._csv_header, lograw_tuple))
        return logdict
