# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.8.0c'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'


def transform(logdata):
    headers = logdata['httpRequest']['headers']
    if len(headers) > 0:
        logdata['httpRequest']['header'] = {}
        for header in headers:
            key = header['name'].lower().replace('-', '_')
            logdata['httpRequest']['header'][key] = header['value']
            if key == 'host':
                logdata['url']['domain'] = header['value']
            elif key == 'user_agent':
                logdata['user_agent'] = {}
                logdata['user_agent']['original'] = header['value']
            elif key == 'referer':
                logdata['http']['request']['referrer'] = header['value']
            elif key == 'authorization':
                del logdata['httpRequest']['header'][key]
    try:
        # WAFv2
        logdata['rule']['ruleset'] = logdata['webaclId'].split('/')[2]
        region_type = logdata['webaclId'].split(':')[5].split('/')[0]
        if region_type == 'global':
            logdata['cloud']['region'] = 'global'
        else:
            logdata['cloud']['region'] = logdata['webaclId'].split(':')[3]
        logdata['cloud']['account'] = {'id': logdata['webaclId'].split(':')[4]}
    except IndexError:
        # WAFv1
        logdata['rule']['ruleset'] = logdata['webaclId']
    logdata['http']['version'] = (logdata['httpRequest']
                                  ['httpVersion'].split('/')[1])
    # action = logdata.get('action')
    # if 'ALLOW' in action:
    #     logdata['event']['outcome'] = 'success'
    # elif 'BLOCK' in action:
    #     logdata['event']['outcome'] = 'failure'
    # else:
    #     logdata['event']['outcome'] = 'unknown'
    return logdata
