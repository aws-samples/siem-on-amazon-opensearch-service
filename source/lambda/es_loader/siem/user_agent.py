# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.8.0c'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import re
import urllib.parse
from functools import lru_cache

from aws_lambda_powertools import Logger
from ua_parser import user_agent_parser

logger = Logger(child=True)

RE_AWS_USER_AGENT = re.compile(r'^(AWS Internal|[\w\.-]+?\.amazonaws.com)$')


@lru_cache(maxsize=100000)
def enrich(original):
    if '%20' in original:
        original = urllib.parse.unquote(original)
    parsed_string = user_agent_parser.Parse(original)

    _ua = parsed_string['user_agent']
    ua_name = _ua['family']
    ua_version = (_ua['major'], _ua['minor'], _ua['patch'])
    ua_version = '.'.join([str(v) for v in ua_version if v])
    _os = parsed_string['os']
    os_name = _os['family']
    os_version = (_os['major'], _os['minor'], _os['patch'], _os['patch_minor'])
    os_version = '.'.join([str(v) for v in os_version if v])
    device_name = parsed_string['device']['family']

    ua_field_data = {'original': original}
    ua_field_data['name'] = ua_name
    if ua_name == 'Other':
        m = RE_AWS_USER_AGENT.match(original)
        if m:
            ua_field_data['name'] = m.group()
    if ua_version:
        ua_field_data['version'] = ua_version
    ua_field_data['os.name'] = os_name
    ua_field_data['os.full'] = os_name
    if os_version:
        ua_field_data['os.version'] = os_version
    if os_name and os_version:
        ua_field_data['os.full'] = f'{os_name} {os_version}'
    ua_field_data['device.name'] = device_name

    return ua_field_data
