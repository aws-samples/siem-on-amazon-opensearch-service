# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.8.0c'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import re
from functools import cached_property

from aws_lambda_powertools import Logger

from siem import FileFormatBase

logger = Logger(child=True)


class FileFormatMultiline(FileFormatBase):
    def __init__(self, rawdata=None, logconfig=None, logtype=None):
        super().__init__(rawdata, logconfig, logtype)
        self._multiline_firstline = None
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
    def multiline_firstline(self):
        return self._multiline_firstline

    @multiline_firstline.setter
    def multiline_firstline(self, multiline_firstline):
        self._multiline_firstline = multiline_firstline

    @cached_property
    def _re_multiline_firstline(self):
        if self.logconfig:
            return self.logconfig['multiline_firstline']
        elif self.multiline_firstline:
            return re.compile(self.multiline_firstline)

    @property
    def log_count(self):
        count = 0
        for line in self.rawdata:
            if self._match_multiline_firstline(line):
                count += 1
        return count

    def _match_multiline_firstline(self, line):
        if self._re_multiline_firstline.match(line):
            return True
        else:
            return False

    def extract_log(self, start, end, logmeta={}):
        count = 0
        multilog = []
        is_in_scope = False
        for line in self.rawdata:
            if self._match_multiline_firstline(line):
                count += 1
                if start <= count <= end:
                    if len(multilog) > 0:
                        # yield previous log
                        lograw = "".join(multilog).rstrip()
                        logdict = self.convert_lograw_to_dict(lograw)
                        yield(lograw, logdict, logmeta)
                    multilog = []
                    is_in_scope = True
                    multilog.append(line)
                elif count > end:
                    break
                else:
                    continue
            elif is_in_scope:
                multilog.append(line)
        if is_in_scope:
            # yield last log
            lograw = "".join(multilog).rstrip()
            logdict = self.convert_lograw_to_dict(lograw)
            yield(lograw, logdict, logmeta)

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
