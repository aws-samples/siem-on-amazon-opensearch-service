# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.8.1-beta.4'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

from siem import utils


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

    category_uid = int(logdata.get('category_uid', ''))
    if category_uid == 2:
        mtime = int(logdata.get('finding', {}).get('modified_time'))
        ctime = int(logdata.get('finding', {}).get('created_time'))
        if mtime:
            logdata['@timestamp'] = mtime
            logdata['__index_dt'] = utils.convert_epoch_to_datetime(mtime)
        elif ctime:
            logdata['@timestamp'] = ctime
            logdata['__index_dt'] = utils.convert_epoch_to_datetime(ctime)

    try:
        logdata['unmapped_original'] = str(logdata.pop('unmapped'))
    except KeyError:
        pass

    return logdata
