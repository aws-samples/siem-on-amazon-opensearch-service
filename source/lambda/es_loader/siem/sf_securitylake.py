# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.10.0-rc.1'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

from siem import utils


def transform(logdata):
    category_name = logdata.get('category_name')
    category_uid = int(logdata.get('category_uid', ''))
    if category_name:
        index_suffix = f"-{category_name.split()[0].lower()}"
        log_type = f"-{category_name.replace(' ', '-').lower()}"
    elif not category_name:
        if category_uid == 1:
            index_suffix = '-system'
            log_type = '-system-activity'
        elif category_uid == 2:
            index_suffix = '-findings'
            log_type = '-findings'
        elif category_uid == 3:
            index_suffix = '-audit'
            log_type = '-audit-activity'
        elif category_uid == 4:
            index_suffix = '-network'
            log_type = '-network-activity'
        elif category_uid == 5:
            index_suffix = '-config'
            log_type = '-config-inventory'
        else:
            index_suffix = ''
            log_type = ''
    logdata['__index_name'] = f'log-ocsf{index_suffix}'
    logdata['@log_type'] = f'ocsf{log_type}'

    if category_uid == 2:
        mtime = logdata.get('finding', {}).get('modified_time')
        ctime = logdata.get('finding', {}).get('created_time')
        if mtime:
            mtime = int(mtime)
            logdata['@timestamp'] = mtime
            logdata['__index_dt'] = utils.convert_epoch_to_datetime(mtime)
        elif ctime:
            ctime = int(ctime)
            logdata['@timestamp'] = ctime
            logdata['__index_dt'] = utils.convert_epoch_to_datetime(ctime)

    try:
        name = logdata['user']['name']
        if ':' in name:
            logdata['user']['name'] = name.split(':')[-1].split('/')[-1]
    except KeyError:
        pass

    return logdata
