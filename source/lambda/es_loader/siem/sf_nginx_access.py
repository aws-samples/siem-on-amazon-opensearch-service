# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.10.3-rc.1'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import re

from siem import utils

# REGEXP
RE_SERVICE_NAME = re.compile(r'/web-site-name=([^/]*?)/')


def extract_instance_id(logdata, web_dict):
    instanceid = utils.extract_aws_instanceid_from_text(
        logdata.get('@log_stream', ""))
    if instanceid:
        hostname = web_dict['url'].get('domain')
        if hostname:
            hosts = [hostname, instanceid]
        else:
            hosts = instanceid
        web_dict['cloud'] = {'instance': {'id': instanceid}}
        web_dict['related']['hosts'] = hosts
    return web_dict


def transform(logdata):
    web_dict = {'http': {}, 'event': {}, 'related': {}, 'url': {}}
    web_dict = extract_instance_id(logdata, web_dict)

    # service.name
    m = RE_SERVICE_NAME.search(logdata['@log_s3key'])
    if m:
        web_dict['service'] = {'name': m.group(1)}

    request_method = logdata.get('request_method')
    request_path = logdata.get('request_path')
    request_version = logdata.get('request_version')
    request_raw = logdata.get('request_raw')

    # http.version, http.request.method
    # url.original, url.domain, url.port
    # url.path, url.extension, url.query, url.fragment
    http, url = utils.extract_url_http_fields_from_http_request(
        request_method, request_path, request_version, request_raw)
    web_dict['http'] = http
    web_dict['url'] = url

    # url.schema
    log_group = logdata.get('@log_group')
    if log_group and 'ssl' in log_group:
        web_dict['url']['scheme'] = 'https'
    elif log_group and 'access' in log_group:
        web_dict['url']['scheme'] = 'http'

    # event.outcome
    try:
        response_status = int(logdata.get('response_status'))
    except Exception:
        response_status = None
    if response_status and response_status < 400:
        web_dict['event']['outcome'] = 'success'
    elif response_status and response_status >= 400:
        web_dict['event']['outcome'] = 'failure'
    else:
        web_dict['event']['outcome'] = 'unknown'

    # related.ip
    # http.request.header.x_forwarded_for
    related_ip = set([logdata['source']['ip']])
    xff_str = logdata.get('xff')
    if xff_str:
        xff_ip_list = utils.parse_xff(xff_str)
        web_dict['http'] = {
            'request': {'header': {'x_forwarded_for': xff_ip_list}}}
        related_ip.update(xff_ip_list)
        web_dict['related']['ip'] = sorted(list(related_ip))

    del logdata['authuser']
    del logdata['datetime']
    del logdata['ident']
    del logdata['request_method']
    del logdata['request_path']
    del logdata['request_raw']
    del logdata['request_version']
    del logdata['referer']
    del logdata['remotehost']
    del logdata['response_body_bytes']
    del logdata['response_status']
    del logdata['useragent']
    del logdata['xff']

    if web_dict:
        logdata = utils.merge_dicts(logdata, web_dict)

    return logdata
