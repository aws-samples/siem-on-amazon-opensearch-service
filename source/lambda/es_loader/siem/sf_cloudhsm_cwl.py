# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.8.0c'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import re

from siem.sf_cloudhsm import transform_hsm

RE_CLUSTER_ID = re.compile(
    r'\W(cluster-[1-9a-z]{11})\W.*/(hsm-[1-9a-z]{11})\W')


def extract_cluster_instance(logdata):
    cluster_id = None
    hsm_id = None
    if logdata.get('@log_s3key'):
        m = RE_CLUSTER_ID.search(logdata['@log_s3key'])
        if m:
            cluster_id = m.group(1)
            hsm_id = m.group(2)
    return cluster_id, hsm_id


def transform(logdata):
    cluster_id, hsm_id = extract_cluster_instance(logdata)
    logdata = transform_hsm(logdata, cluster_id, hsm_id)
    return logdata
