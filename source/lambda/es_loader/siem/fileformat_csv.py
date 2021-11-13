# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.5.1-beta.3'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

from functools import cached_property

from aws_lambda_powertools import Logger

from siem import FileFormatBase, utils

logger = Logger(child=True)


class FileFormatCsv(FileFormatBase):
    @cached_property
    def log_count(self):
        # _log_count = len(self.rawdata.readlines())
        return sum(1 for line in self.rawdata)

    @property
    def ignore_header_line_number(self):
        # to exclude CSV Header
        return 1

    @cached_property
    def _csv_header(self):
        return self.rawdata.readlines()[0].strip().split()

    def extract_log(self, start, end, logmeta={}):
        start_index = start - 1
        end_index = end
        for logdata in self.rawdata.readlines()[start_index:end_index]:
            lograw = logdata.strip()
            logdict = self.convert_lograw_to_dict(lograw)
            yield (lograw, logdict, logmeta)

    def convert_lograw_to_dict(self, lograw, logconfig=None):
        logdict = dict(zip(self._csv_header, lograw.split()))
        logdict = utils.convert_keyname_to_safe_field(logdict)
        return logdict
