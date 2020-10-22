# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import re

RE_REGION = re.compile('(global|(us|ap|ca|eu|me|sa|af)-[a-zA-Z]+-[0-9])')


def transform(logdata):
    try:
        logdata['user']['name'] = logdata['user']['name'].split('/')[-1]
    except KeyError:
        pass

    if logdata['cloud']['region'] == 'unknown':
        m = RE_REGION.search(logdata['EndPoint'])
        if m:
            logdata['cloud']['region'] = m.group(1)

    return logdata
