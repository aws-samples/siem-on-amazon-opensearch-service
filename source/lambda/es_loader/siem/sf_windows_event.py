# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.8.0c'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

from siem import utils
from siem.fileformat_winevtxml import initial_extract_action_outcome


def extract_instance_id(logdata, win_dict):
    instanceid = utils.extract_aws_instanceid_from_text(
        logdata.get('@log_stream', ''))
    if instanceid:
        win_dict['cloud'] = {'instance': {'id': instanceid}}
    return win_dict


def transform(logdata):
    win_dict = initial_extract_action_outcome(logdata)
    win_dict = extract_instance_id(logdata, win_dict)

    logdata = utils.merge_dicts(logdata, win_dict)

    return logdata
