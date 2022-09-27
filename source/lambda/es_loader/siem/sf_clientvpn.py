# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.8.0c'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'


def transform(logdata):
    if logdata.get('connection-attempt-status') == 'successful':
        logdata['event']['outcome'] = 'success'
    elif logdata.get('connection-attempt-status') == 'failed':
        logdata['event']['outcome'] = 'failure'

    if logdata.get('connection-attempt-failure-reason') != 'NA':
        logdata['error'] = {
            'message': logdata['connection-attempt-failure-reason']}

    bytes = (int(logdata.get('egress-bytes', 0))
             + int(logdata.get('ingress-bytes', 0)))
    packets = (int(logdata.get('egress-packets', 0))
               + int(logdata.get('ingress-packets', 0)))
    if bytes != 0 or packets != 0:
        logdata['network'] = {'bytes': bytes, 'packets': packets}

    start_time = logdata.get('connection-start-time')
    if start_time == 'NA':
        del logdata['connection-start-time']
    elif start_time and start_time != 'NA':
        logdata['connection-start-time'] = (
            logdata['connection-start-time'].replace(' ', 'T') + '+00:00')

    end_time = logdata.get('connection-end-time')
    if end_time == 'NA':
        del logdata['connection-end-time']
    elif end_time and end_time != 'NA':
        logdata['connection-end-time'] = (
            logdata['connection-end-time'].replace(' ', 'T') + '+00:00')

    logdata['connection-last-update-time'] = (
        logdata['connection-last-update-time'].replace(' ', 'T') + '+00:00')

    if logdata.get('connection-duration-seconds') != 'NA':
        logdata['event']['duration'] = (
            int(logdata['connection-duration-seconds']) * 1000 * 1000 * 1000)

    return logdata
