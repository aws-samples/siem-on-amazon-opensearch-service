# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.7.2-beta.3'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

from functools import cached_property

import pandas as pd
from aws_lambda_powertools import Logger

from siem import FileFormatBase

logger = Logger(child=True)


class FileFormatParquet(FileFormatBase):
    def __init__(self, rawdata=None, logconfig=None, logtype=None):
        super().__init__(rawdata, logconfig, logtype)
        self.df = pd.read_parquet(rawdata)

    @cached_property
    def log_count(self):
        return len(self.df.index)

    def extract_log(self, start, end, logmeta={}):
        start_index = start - 1
        end_index = end
        for i in range(start_index, end_index):
            df_clean = self.df[i:i + 1].dropna(axis=1, how='all')
            df_dict = df_clean.to_dict(orient='records')[0]
            yield (str(df_dict), df_dict, logmeta)

    def convert_lograw_to_dict(self, lograw, logconfig=None):
        return lograw
