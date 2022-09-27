# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.8.0c'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import re

from siem import utils

# REGEXP
RE_LIST_SSHD = [
    re.compile(r'(?P<action>Accepted|Failed|failure|Invalid user|invalid user)\s.*?((publickey|password|none) for )?(invalid user )?(?P<user>\S+)(\s+from.*?(?P<source_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))?(\s+port\s+(?P<source_port>\S+))?'),
    re.compile(r'^(?P<action>(Disconnected|Received disconnect)) from (?P<source_ip>[^ ]*) port (?P<source_port>\d+)'),
    re.compile(r'^(?P<action>error): AuthorizedKeysCommand \S+ (?P<user>\S+) (SHA|RSA)'),
    re.compile(r'^pam_unix(\S+): (?P<action>session closed) for user (?P<user>\S+)'),
    re.compile(r'^pam_unix(\S+): (?P<action>session opened) for user \S+ by (?P<user>\S*)\('),
    re.compile(r'^(?P<action>Connection (reset|closed))\s+by\s+(?P<source_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+port\s+(?P<source_port>\S+)'),
    re.compile(r'.+\s+(from|with)\s+(?P<source_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+port\s+(?P<source_port>\S+)'),
    re.compile(r'^(?P<action>reverse mapping checking).*\[(?P<source_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]'),
    re.compile(r'\s(?P<source_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s'),
]
RE_LIST_SUDO = [
    re.compile(r'^(?P<user>\S+) : .*COMMAND=(?P<action>.*)'),
    re.compile(r'^pam_unix(\S+): (?P<action>session closed) for user (?P<user>\S+)'),
    re.compile(r'^pam_unix(\S+): (?P<action>session opened) for user \S+ by (?P<user>\S*)\('),
]


def extract_instance_id(logdata, linux_dict):
    instanceid = utils.extract_aws_instanceid_from_text(
        logdata.get('@log_stream', ""))
    if instanceid:
        linux_dict = {'cloud': {'instance': {'id': instanceid}},
                      'related': {'hosts': [logdata['hostname'], instanceid]}}
    return linux_dict


def extract_from_sshd(logdata, linux_dict):
    linux_dict['event'] = {'module': 'secure'}
    data = {}
    for RE_SSHD in RE_LIST_SSHD:
        m = RE_SSHD.search(logdata['syslog_message'])
        if m:
            for key in m.groupdict():
                data[key] = m.group(key)
            break
    if 'user' in data:
        linux_dict['user'] = {'name': data['user']}
    if 'source_ip' in data:
        linux_dict['source'] = {
            'ip': data['source_ip'], 'port': data.get('source_port', '')}
    if 'action' in data:
        linux_dict['event']['category'] = 'authentication'
        linux_dict['event']['action'] = data['action']
        action = data['action'].lower()
        if 'accept' in action or 'opened' in action:
            linux_dict['event']['outcome'] = 'success'
        elif 'fail' in action or 'invalid' in action or 'err' in action:
            linux_dict['event']['outcome'] = 'failure'
        elif 'disconnect' in action or 'reset' in action or 'close' in action:
            # linux_dict['event']['outcome'] is empty for disconnection event
            pass
        else:
            linux_dict['event']['outcome'] = 'unknown'
    return linux_dict


def extract_from_sudo(logdata, linux_dict):
    linux_dict['event'] = {'module': 'secure'}
    data = {}
    for RE_SUDO in RE_LIST_SUDO:
        m = RE_SUDO.search(logdata['syslog_message'])
        if m:
            for key in m.groupdict():
                data[key] = m.group(key)
            break
    if 'user' in data:
        linux_dict['user'] = {'name': data['user']}
    if 'action' in data:
        linux_dict['user'] = {'name': data['user']}
        linux_dict['event'] = {
            'action': data['action'], 'outcome': 'success'}
    return linux_dict


def extract_related_ip_user(linux_dict):
    if 'related' not in linux_dict:
        linux_dict['related'] = {}
    if 'user' in linux_dict:
        linux_dict['related']['user'] = linux_dict['user']['name']
    if 'source' in linux_dict:
        linux_dict['related']['ip'] = linux_dict['source']['ip']
    return linux_dict


def transform(logdata):
    proc = logdata.get('proc', "")
    linux_dict = {}
    linux_dict = extract_instance_id(logdata, linux_dict)

    # /var/log/secure
    if 'sshd' in proc:
        logdata['__index_name'] = 'log-linux-secure'
        linux_dict = extract_from_sshd(logdata, linux_dict)
    elif 'sudo' in proc:
        logdata['__index_name'] = 'log-linux-secure'
        linux_dict = extract_from_sudo(logdata, linux_dict)
        pass
    elif 'su' == proc:
        logdata['__index_name'] = 'log-linux-secure'
    else:
        pass
    linux_dict = extract_related_ip_user(linux_dict)

    if linux_dict:
        logdata = utils.merge_dicts(logdata, linux_dict)
    return logdata
