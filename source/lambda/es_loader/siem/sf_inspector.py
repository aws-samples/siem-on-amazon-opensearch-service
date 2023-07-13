# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.10.0-beta.3'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import datetime
import hashlib


def transform(logdata):
    logdata['@id'] = hashlib.md5(logdata['findingArn'].encode()).hexdigest()
    # confirmd and ignored Rule-143469

    last_observed_epoch_str = str(int(datetime.datetime.strptime(
        logdata['updatedAt'], '%b %d, %Y, %I:%M:%S %p').timestamp()))
    logdata['__doc_id_suffix'] = last_observed_epoch_str

    if 'AWS_ECR_CONTAINER_IMAGE' in logdata['vulnerability'].get('category'):
        try:
            del logdata['related']['hosts']
        except Exception:
            # pass
            # to ignore Rule-269212
            None
        try:
            del logdata['cloud']['instance']['id']
        except Exception:
            # pass
            # to ignore Rule-269212
            None

    if 'PACKAGE_VULNERABILITY' in logdata['type']:
        logdata['rule']['id'] = (
            f"PACKAGE_VULNERABILITY_{logdata['vulnerability']['id']}")
    elif 'NETWORK_REACHABILITY' in logdata['type']:
        details = logdata['networkReachabilityDetails']
        logdata['rule']['id'] = (
            f"NETWORK_REACHABILITY_{details['protocol']}"
            f"_{details['openPortRange']['begin']}"
            f"_{details['openPortRange']['end']}")

    if logdata.get('description'):
        try:
            remediation = logdata['remediation']['recommendation']['text']
            logdata['vulnerability']['description'] = (
                f"{logdata['description']}\n\nRemediation: {remediation}")
        except (KeyError, TypeError):
            pass

    return logdata
