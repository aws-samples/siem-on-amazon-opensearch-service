# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.6.1-beta.2'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

from functools import cached_property

from aws_lambda_powertools import Logger

from siem import FileFormatBase

logger = Logger(child=True)


class FileFormatText(FileFormatBase):
    @cached_property
    def _re_log_pattern_prog(self):
        try:
            return self.logconfig['log_pattern']
        except AttributeError:
            msg = 'No log_pattern(regex). You need to define it in user.ini'
            logger.exception(msg)
            raise AttributeError(msg) from None

    @property
    def log_count(self):
        # _log_count = len(self.rawdata.readlines())
        _log_count = sum(1 for line in self.rawdata)
        return _log_count

    @property
    def ignore_header_line_number(self):
        return self.logconfig['text_header_line_number']

    def extract_log(self, start, end, logmeta={}):
        start_index = start - 1
        end_index = end
        for logdata in self.rawdata.readlines()[start_index:end_index]:
            lograw = logdata.strip()
            logdict = self.convert_lograw_to_dict(lograw)
            yield (lograw, logdict, logmeta)

    def convert_lograw_to_dict(self, lograw, logconfig=None):
        m = self._re_log_pattern_prog.match(lograw)
        if m:
            logdata_dict = m.groupdict()
        else:
            msg_dict = {
                'Exception': f'Invalid regex pattern of {self.logtype}',
                'rawdata': lograw, 'regex_pattern': self._re_log_pattern_prog}
            logger.error(msg_dict)
            raise Exception(repr(msg_dict))
        return logdata_dict
