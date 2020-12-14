# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import urllib.parse
import re

RE_CLOUDFRONT_DIST_ID = re.compile('[0-9A-Z]{14}')


def transform(logdata):
    if logdata['cs_uri_query'] != '-':
        q = '?' + logdata['cs_uri_query']
    else:
        q = ''
    url_host = logdata['cs_protocol'] + '://' + logdata['x_host_header']
    path = logdata['cs_uri_stem']
    logdata['url']['full'] = url_host + path + q
    logdata['http']['version'] = logdata['cs_protocol_version'].split('/')[1]
    try:
        ua = logdata['user_agent']['original']
        logdata['user_agent']['original'] = urllib.parse.unquote(ua)
    except Exception:
        pass

    m = RE_CLOUDFRONT_DIST_ID.search(logdata['@log_s3key'])
    if m:
        logdata['distribution_id'] = m.group(0)
    else:
        logdata['distribution_id'] = "unknown"

    return logdata
