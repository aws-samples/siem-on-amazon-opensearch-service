# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.8.0c'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

from siem.sf_config_snapshot import (extract_host, extract_ip, extract_user,
                                     update_doc_ids)


def transform(logdata):
    logdata = update_doc_ids(logdata)
    logdata = extract_host(logdata)
    logdata = extract_user(logdata)
    logdata = extract_ip(logdata)

    try:
        compliance = logdata['newEvaluationResult']['complianceType']
    except KeyError:
        compliance = None
    if compliance:
        if compliance == 'COMPLIANT':
            logdata['event']['outcome'] = 'success'
        elif compliance == 'NON_COMPLIANT':
            logdata['event']['outcome'] = 'failure'
        else:
            # INSUFFICIENT_DATA
            # NOT_APPLICABLE
            logdata['event']['outcome'] = 'unknown'

    return logdata
