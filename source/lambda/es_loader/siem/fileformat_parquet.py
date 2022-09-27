# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.8.0c'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

from datetime import datetime
from functools import cached_property

try:
    import numpy as np
    import pandas as pd
except ImportError:
    np = None
    pd = None
from aws_lambda_powertools import Logger

from siem import FileFormatBase

logger = Logger(child=True)


def clean_dict(d):
    for key, value in list(d.items()):
        if isinstance(value, dict):
            clean_dict(value)
        if np:
            if isinstance(value, np.ndarray):
                value = value.tolist()
                d[key] = value
        if isinstance(value, datetime):
            d[key] = value.isoformat()
    return d


class FileFormatParquet(FileFormatBase):
    def __init__(self, rawdata=None, logconfig=None, logtype=None):
        super().__init__(rawdata, logconfig, logtype)
        if pd is None:
            return None
        self.df = pd.read_parquet(rawdata)

    @cached_property
    def log_count(self):
        if pd is None:
            logger.error('You need to deploy Pandas as Lambda layer manually')
            return 0
        return len(self.df.index)

    def extract_log(self, start, end, logmeta={}):
        start_index = start - 1
        end_index = end
        for i in range(start_index, end_index):
            df_clean = self.df[i:i + 1].dropna(axis=1, how='all')
            df_dict = df_clean.to_dict(orient='records')[0]
            df_dict = clean_dict(df_dict)
            yield (str(df_dict), df_dict, logmeta)

    def convert_lograw_to_dict(self, lograw, logconfig=None):
        return lograw
