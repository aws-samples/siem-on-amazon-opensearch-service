# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from siem import utils
from siem.winevtxml import initial_extract_action_outcome
from siem.sf_windows_event import extract_instance_id


def transform(logdata):
    win_dict = initial_extract_action_outcome(logdata)
    win_dict = extract_instance_id(logdata, win_dict)

    logdata = utils.merge_dicts(logdata, win_dict)

    return logdata
