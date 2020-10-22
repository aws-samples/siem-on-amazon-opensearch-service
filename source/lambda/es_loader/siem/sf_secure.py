# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import re
import siem


def transform(logdata):
    instanceid = siem.re_instanceid.search(
        logdata.get('@log_stream', ""))
    if instanceid:
        secure_dict = {'cloud': {'instance': {'id': instanceid.group(1)}}}
    if 'sshd' in logdata.get('proc'):
        p = (r"(?P<action>Accepted|Failed|failure|(?:Invalid user)).*?"
             r"(?P<user>\S+)\s+from.*?(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}"
             r"\.\d{1,3})(?:\s+port\s+(?P<port>\S+)\s+\w?\s*(ssh\d))?")
        m = re.match(p, logdata.get('message'))
        if m:
            action = m.group('action').lower()
            secure_dict['event'] = {'action': action,
                                    'category': 'authentication'}
            secure_dict['source'] = {'ip': m.group('ip'),
                                     'port': m.group('port')}
            secure_dict['user'] = {'name': m.group('user'),
                                   'id': m.group('user')}
            if 'accepted' in action:
                logdata['event']['outcome'] = 'success'
            elif action in ('failed', 'failure', 'invalid user'):
                logdata['event']['outcome'] = 'failure'
    siem.merge(logdata, secure_dict)
    return logdata
