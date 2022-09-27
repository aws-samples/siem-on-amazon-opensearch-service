# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.8.0c'
__license__ = 'MIT-0'
__author__ = 'Shunsuke Goto'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import re
from functools import cached_property

from aws_lambda_powertools import Logger

from siem import FileFormatBase

logger = Logger(child=True)

RE_LOGRAW = r'((CEF:\s?\d+)([^=\\]+\|){,7})(.*)'
RE_HEADER = r'(?<!\\)\|'
RE_EXTENSION = r'([^=\s]+)=((?:[\\]=|[^=])+)(?:\s|$)'


class FileFormatCef(FileFormatBase):
    @cached_property
    def log_count(self):
        return sum(1 for line in self.rawdata)

    def extract_log(self, start=0, end=0, logmeta={}):
        start_index = start - 1
        end_index = end
        for logdata in self.rawdata.readlines()[start_index:end_index]:
            lograw = logdata.strip()
            logdict = self.convert_lograw_to_dict(lograw)
            yield (lograw, logdict, logmeta)

    def convert_lograw_to_dict(self, lograw, logconfig=None):
        logdict = dict()
        res = re.search(RE_LOGRAW, lograw)
        if not res:
            logger.warning('This log will be loaded, '
                           'but not parsed because of invalid cef')
            logdict = {'__skip_normalization': True,
                       '__error_message': 'invalid cef file'}
            return logdict

        header = res.group(1)
        header_splits = re.split(RE_HEADER, header)

        logdict['cef_version'] = header_splits[0].split(':')[-1].strip()
        logdict['cef_device_vendor'] = header_splits[1]
        logdict['cef_device_product'] = header_splits[2]
        logdict['cef_device_version'] = header_splits[3]
        logdict['cef_device_event_class_id'] = header_splits[4]
        logdict['cef_name'] = header_splits[5]
        if len(header_splits) > 6:
            logdict['cef_severity'] = header_splits[6]

        extension = res.group(4)
        extension_dict = dict()
        for key, value in re.findall(RE_EXTENSION, extension):
            extension_dict[key] = value

        for key in list(extension_dict.keys()):
            if key[-5:] == 'Label':
                custom_label = key[:-5]
                if custom_label in extension_dict.keys():
                    extension_dict[extension_dict[key]] \
                        = extension_dict[custom_label]
                    del extension_dict[custom_label]
                    del extension_dict[key]

        logdict.update(extension_dict)

        return logdict
