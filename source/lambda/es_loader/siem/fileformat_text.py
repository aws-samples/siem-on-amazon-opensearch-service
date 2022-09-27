# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.8.0c'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

from functools import cached_property

from aws_lambda_powertools import Logger

from siem import FileFormatBase

logger = Logger(child=True)


class FileFormatText(FileFormatBase):
    def __init__(self, rawdata=None, logconfig=None, logtype=None):
        super().__init__(rawdata, logconfig, logtype)
        self._regex_error_count = {}
        if logtype not in self._regex_error_count:
            self._regex_error_count[logtype] = 0
        self._re_log_pattern_prog

    @cached_property
    def _re_log_pattern_prog(self):
        try:
            return self.logconfig['log_pattern']
        except AttributeError:
            msg = (f'Invalid regex pattern of {self.logtype}. '
                   'You need to define it in user.ini')
            logger.critical(msg)
            raise AttributeError(msg) from None
        except KeyError:
            msg = (f'There is no regex pattern of {self.logtype}. '
                   'You need to define log_pattern in user.ini')
            logger.critical(msg)
            raise KeyError(msg) from None

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
            msg = f'Invalid regex pattern of {self.logtype}'
            extra = {'message_rawdata': lograw,
                     'message_regex_pattern': self._re_log_pattern_prog}
            self._regex_error_count[self.logtype] += 1
            if self._regex_error_count[self.logtype] < 10:
                logger.error(msg, extra=extra)
            elif self._regex_error_count[self.logtype] == 11:
                msg_crit = ('There are more than 10 regex errors of '
                            f'{self.logtype}. The error logs are suppressed '
                            'now. Logs that will cause future regex errors '
                            'will not be ingested into OpenSearch and will '
                            'not be output to the error logs')
                logger.critical(msg_crit)
            return 'regex_error'

        return logdata_dict
