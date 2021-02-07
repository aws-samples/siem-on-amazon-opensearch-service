# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import re
from siem import utils

# REGEXP
RE_LIST_SSHD = [
    re.compile(r'(?P<action>Accepted|Failed|failure|Invalid user|invalid user)\s.*?(publickey for )?(?P<user>\S+)(\s+from.*?(?P<source_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))?(\s+port\s+(?P<source_port>\S+))?'),
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
        linux_dict = {'cloud': {'instance': {'id': instanceid}}}
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
        if ('accept' in data['action'].lower()
                or 'isconnect' in data['action'].lower()
                or 'opened' in data['action'].lower()):
            logdata['event']['outcome'] = 'success'
        elif ('fail' in data['action'].lower()
                or 'invalid' in data['action'].lower()
                or 'err' in data['action'].lower()):
            logdata['event']['outcome'] = 'failure'
        elif ('isconnect' in data['action'].lower()
                or 'reset' in data['action'].lower()
                or 'close' in data['action'].lower()):
            # logdata['event']['outcome'] is empty for disconnection event
            pass
        else:
            logdata['event']['outcome'] = 'unknown'
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

    if linux_dict:
        logdata = utils.merge_dicts(logdata, linux_dict)
    return logdata
