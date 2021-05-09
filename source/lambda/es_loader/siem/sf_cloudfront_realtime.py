# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import re
import urllib.parse

RE_CLOUDFRONT_DIST_ID = re.compile('[0-9A-Z]{13,14}')


def transform(logdata):
    logdata['url']['path'] = logdata['url']['path'].split('?')[0]
    logdata['url']['full'] = (logdata['cs_protocol'] + '://'
                              + logdata['cs_host'] + logdata['cs_uri_stem'])
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
