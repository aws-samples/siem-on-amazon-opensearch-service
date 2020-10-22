# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import re
import siem


def transform(logdata):
    # event (ecs)
    module = (logdata['ProductFields']['aws/securityhub/ProductName']).lower()
    logdata['event']['module'] = module
    if module in ('guardduty', 'macie'):
        logdata['event']['category'] = 'intrusion_detection'
    elif 'inspecotor' in module:
        logdata['event']['category'] = 'package'
    if logdata['event']['module'] in ('inspector', 'guardduty'):
        instanceid = siem.re_instanceid.search(logdata['Title'])
        if instanceid:
            logdata['cloud']['instance'] = {'id': instanceid.group(1)}
    if 'guardduty' in module:
        msg = str(logdata['Resources'])
        p = r"UserName': '([0-9a-zA-Z-_]*)'.*:AccessKey:(\w*)'"
        m = re.search(p, msg)
        if m:
            _name = m.group(1)
            _id = m.group(2)
            new_dict = {'user': {'id': _id, 'name': _name}}
            siem.merge(logdata, new_dict)
    return logdata
