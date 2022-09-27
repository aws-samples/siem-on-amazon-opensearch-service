# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.8.0c'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

from siem import utils
from siem.sf_linux_os_syslog import (extract_from_sshd, extract_from_sudo,
                                     extract_instance_id,
                                     extract_related_ip_user)


def transform(logdata):
    proc = logdata.get('proc', "")
    linux_dict = {}
    linux_dict = extract_instance_id(logdata, linux_dict)
    if 'sshd' in proc:
        linux_dict = extract_from_sshd(logdata, linux_dict)
    elif 'sudo' in proc:
        linux_dict = extract_from_sudo(logdata, linux_dict)
    linux_dict = extract_related_ip_user(linux_dict)

    if linux_dict:
        logdata = utils.merge_dicts(logdata, linux_dict)
    return logdata
