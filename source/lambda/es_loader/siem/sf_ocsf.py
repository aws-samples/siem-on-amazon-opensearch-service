# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.8.0c'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'


def transform(logdata):
    category_name = logdata.get('category_name')
    if not category_name:
        category = logdata.get('category')
        if category:
            category_name = category
            logdata['category_name'] = logdata.pop('category')
    if category_name:
        index_suffix = f'-{category_name.split()[0].lower()}'
        log_type = category_name.replace(' ', '-').lower()
        logdata['@log_type'] = f'ocsf-{log_type}'
    else:
        index_suffix = ''
    logdata['__index_name'] = f'log-ocsf{index_suffix}'

    try:
        dummpy = logdata['origin']['cloud']['provider']
        del dummpy
    except Exception:
        del logdata['cloud']['provider']

    return logdata
