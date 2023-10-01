# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.10.2-beta.2'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import re

from siem import utils

# REGEXP
RE_SERVICE_NAME = re.compile(r'/web-site-name=([^/]*?)/')
RE_REFERER = re.compile(r'referer:\s*(http[^ ]*)')


def extract_instance_id(logdata, web_dict):
    instanceid = utils.extract_aws_instanceid_from_text(
        logdata.get('@log_stream', ""))
    if instanceid:
        hostname = logdata.get('hostname')
        if hostname:
            hosts = [hostname, instanceid]
        else:
            hosts = instanceid
        web_dict['cloud'] = {'instance': {'id': instanceid}}
        web_dict['related']['hosts'] = hosts
    return web_dict


def transform(logdata):
    web_dict = {'event': {}, 'related': {}, 'url': {}}
    web_dict = extract_instance_id(logdata, web_dict)

    # service.name
    m = RE_SERVICE_NAME.search(logdata['@log_s3key'])
    if m:
        web_dict['service'] = {'name': m.group(1)}

    # http.request.referrer
    if logdata.get('message'):
        m = RE_REFERER.search(logdata['message'])
        if m:
            web_dict['http'] = {'request': {'referrer': m.group(1)}}

    # url.schema
    log_group = logdata.get('@log_group')
    if log_group and 'ssl' in log_group:
        web_dict['url']['scheme'] = 'https'
    elif log_group and 'error' in log_group:
        web_dict['url']['scheme'] = 'http'

    # event.type
    if logdata['log_level'] == 'info':
        web_dict['event']['type'] = 'info'
    elif logdata['log_level'] in ("emerg", "alert", "crit", "error", "warn"):
        web_dict['event']['type'] = 'error'

    del logdata['client_ip']
    del logdata['client_port']
    del logdata['datetime']
    del logdata['debug_message']
    del logdata['log_level']
    del logdata['message']
    del logdata['message_code']
    del logdata['module']
    del logdata['pid']
    del logdata['tid']

    if web_dict:
        logdata = utils.merge_dicts(logdata, web_dict)

    return logdata
