# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.10.2-beta.2'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import ipaddress
import re
import urllib.parse

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
    web_dict = {'event': {}, 'related': {}, 'url': {}}
    web_dict = extract_instance_id(logdata, web_dict)
    related_ip = set([logdata['source']['ip']])

    # service.name
    m = RE_SERVICE_NAME.search(logdata['@log_s3key'])
    if m:
        web_dict['service'] = {'name': m.group(1)}

    # url.domain, url.port
    request_path = logdata.get('request_path', '')
    if request_path is None:
        request_path = ''
    if request_path.startswith('/'):
        pass
    elif (request_path.startswith('http://')
            or request_path.startswith('https://')):
        try:
            req_path_list = request_path.split('/', 3)
            domain_org = req_path_list[2]
            request_path = '/' + req_path_list[-1]
            domain_org_split = domain_org.split(':')
            if len(domain_org_split) == 1:
                web_dict['url']['domain'] = domain_org.split(':')[0]
            elif len(domain_org_split) == 2:
                # ipv4 or domain
                web_dict['url']['domain'] = domain_org.split(':')[0]
                web_dict['url']['port'] = domain_org.split(':')[1]
        except Exception:
            pass
    elif (logdata.get('request_method')
            and logdata['request_method'].lower() == 'connect'):
        path_temp_list = request_path.split(':')
        if len(path_temp_list) == 2:
            web_dict['url']['domain'] = path_temp_list[0]
            web_dict['url']['port'] = path_temp_list[1]
            request_path = ''

    # urldecode
    if '%' in request_path:
        try:
            request_path = urllib.parse.unquote(request_path, errors='strict')
        except Exception:
            request_path = request_path
    # url.fragment
    temp_path_list = request_path.rsplit('#', 1)
    if len(temp_path_list) == 2:
        web_dict['url']['fragment'] = temp_path_list[1]
        request_path = temp_path_list[0]
    # url.path, url.query
    temp_path_list = request_path.split('?', 1)
    web_dict['url']['path'] = temp_path_list[0]
    if len(temp_path_list) == 2:
        web_dict['url']['query'] = temp_path_list[1]
    # url.extension
    filename = web_dict['url']['path'].split('/')[-1]
    if not filename.startswith('.') and '.' in filename:
        web_dict['url']['extension'] = filename.split('.')[-1]

    # url.original
    if logdata.get('request_raw'):
        web_dict['url']['original'] = logdata.get('request_raw')

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

    # http.request.header.x_forwarded_for
    if logdata.get('xff'):
        xff = logdata['xff']
        remote_ip_list = []
        for ip_raw in xff.split(','):
            ip_raw = ip_raw.strip()
            try:
                ipaddress.ip_address(ip_raw.strip())
                remote_ip_list.append(ip_raw)
            except Exception:
                continue
        if len(remote_ip_list):
            web_dict['http'] = {
                'request': {'header': {'x_forwarded_for': remote_ip_list}}}
            related_ip.update(remote_ip_list)

    # related.ip
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
