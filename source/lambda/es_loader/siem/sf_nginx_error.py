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
RE_MESSAGE = re.compile(
    r'client: (?P<client_ip>[0-9a-f.:]+), server: (-|(?P<server>[^ ]*?))'
    r'(?:, request: \"((?P<request_method>[A-Z]+?) (?P<request_path>\/.+?) '
    r'HTTP/(?P<request_version>[^ ]*)|(?P<request_raw>.*?))\")?'
    r'(?:, upstream: \"(?P<upstream>.+?)\")?'
    r'(?:, host: \"(?P<host>[^ ]+?)\")?'
    r'(?:, referrer: \"(?P<referrer>[^ ]+?)\")?$')

# grep server /var/log/nginx/error.log |grep client | awk -F'\*[0-9]+ ' '{print $2}


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
        web_dict['related'] = {'hosts': hosts}
    return web_dict


def transform(logdata):
    web_dict = {'event': {}, 'url': {}}
    web_dict = extract_instance_id(logdata, web_dict)

    # service.name
    m = RE_SERVICE_NAME.search(logdata['@log_s3key'])
    if m:
        web_dict['service'] = {'name': m.group(1)}

    # http.request.referrer
    if logdata.get('message'):
        m = RE_MESSAGE.search(logdata['message'])
        if m:
            web_dict['http'] = {'request': {}}

            client_ip = m.groupdict().get('client_ip')
            server = m.groupdict().get('server')
            request_method = m.groupdict().get('request_method')
            request_path = m.groupdict().get('request_path')
            request_version = m.groupdict().get('request_version')
            request_raw = m.groupdict().get('request_raw')
            upstream = m.groupdict().get('upstream')
            host = m.groupdict().get('host')
            referrer = m.groupdict().get('referrer')

            if client_ip:
                web_dict['source'] = {'ip': client_ip, 'address': client_ip}
            # http.request.method
            if request_method:
                web_dict['http']['request']['method'] = request_method
            # http.version
            if request_version:
                web_dict['http']['version'] = request_version
            # url.original
            if request_raw:
                web_dict['url']['original'] = request_raw
            # url.domain
            if host:
                web_dict['url']['domain'] = host
            # http.request.referer
            if referrer:
                web_dict['http']['request']['referrer'] = referrer

            #related.ip
            #server,
            #related.host
            #web_dict['related'] = {'ip': client_ip}


    # url.schema
    log_group = logdata.get('@log_group')
    if log_group and 'ssl' in log_group:
        web_dict['url']['scheme'] = 'https'
    elif log_group and 'error' in log_group:
        web_dict['url']['scheme'] = 'http'

    # nginx.error.connection_id
    if logdata.get('connection_id'):
        web_dict['nginx'] = {
            'error': {'connection_id': logdata.get('connection_id')}}

    del logdata['connection_id']
    del logdata['datetime']
    del logdata['message']
    del logdata['process_id']
    del logdata['thread_id']
    del logdata['severity']

    if web_dict:
        logdata = utils.merge_dicts(logdata, web_dict)

    return logdata
