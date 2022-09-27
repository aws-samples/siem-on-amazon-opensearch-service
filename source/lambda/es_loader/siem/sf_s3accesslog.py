# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.8.0c'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import re

RE_REGION = re.compile('(global|(us|ap|ca|eu|me|sa|af)-[a-zA-Z]+-[0-9])')


def transform(logdata):
    try:
        logdata['user']['name'] = logdata['user']['name'].split('/')[-1]
    except KeyError:
        pass

    if logdata['cloud']['region'] == 'unknown':
        m = RE_REGION.search(logdata['EndPoint'])
        if m:
            logdata['cloud']['region'] = m.group(1)

    return logdata
