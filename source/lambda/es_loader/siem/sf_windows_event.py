# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from siem import utils


def extract_instance_id(logdata, win_dict):
    instanceid = utils.extract_aws_instanceid_from_text(
        logdata.get('@log_stream', ""))
    if instanceid:
        win_dict = {'cloud': {'instance': {'id': instanceid}}}
    return win_dict


def transform(logdata):
    win_dict = {}
    win_dict = extract_instance_id(logdata, win_dict)

    if win_dict:
        logdata = utils.merge_dicts(logdata, win_dict)

    return logdata
