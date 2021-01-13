# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from siem.sf_linux_os_syslog import (
    extract_instance_id, extract_from_sshd, extract_from_sudo)
from siem import utils


def transform(logdata):
    proc = logdata.get('proc', "")
    linux_dict = {}
    linux_dict = extract_instance_id(logdata, linux_dict)
    if 'sshd' in proc:
        linux_dict = extract_from_sshd(logdata, linux_dict)
    elif 'sudo' in proc:
        linux_dict = extract_from_sudo(logdata, linux_dict)

    if linux_dict:
        logdata = utils.merge_dicts(logdata, linux_dict)
    return logdata
