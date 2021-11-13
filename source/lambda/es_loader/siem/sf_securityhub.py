# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.5.1-beta.3'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import re
from datetime import datetime

from siem import utils

RE_GDTYPE = re.compile(r"/(?P<ThreatPurpose>\w+)"
                       r"(:|/)(?P<ResourceTypeAffected>\w*)"
                       r"(/|.|-)(?P<ThreatFamilyName>[\w\&]*)")


def get_values_from_asff_resources(resources):
    resouce_dict = {}
    for resouce in resources:
        if resouce['Type'] == 'AwsEc2Instance':
            instanceid = resouce['Id'].split('/')[-1]
            resouce_dict['cloud'] = {'instance': {'id': instanceid}}
        elif resouce['Type'] == 'AwsIamAccessKey':
            accesskey = resouce['Id'].split(':')[-1]
            if accesskey == 'null':
                accesskey = (resouce['Details']['AwsIamAccessKey']
                             ['PrincipalId']).split(':')[0]
            name = resouce['Details']['AwsIamAccessKey']['PrincipalName']
            resouce_dict['user'] = {'id': accesskey, 'name': name}
        elif resouce['Type'] == 'AwsEc2Volume':
            try:
                instanceid = (resouce['Details']['AwsEc2Volume']['Attachments']
                              [0]['InstanceId'])
            except Exception:
                continue
            resouce_dict['cloud'] = {'instance': {'id': instanceid}}
        elif resouce['Type'] == 'AwsIamRole':
            name = resouce['Id'].split('/')[-1]
            resouce_dict['user'] = {'name': name}
        elif resouce['Type'] == 'AwsS3Bucket':
            pass

    return resouce_dict


def transform(logdata):
    # event (ecs)
    module = (logdata['ProductFields']['aws/securityhub/ProductName']).lower()
    logdata['event']['module'] = module

    if 'guardduty' in module:
        logdata['event']['category'] = 'intrusion_detection'

        m = RE_GDTYPE.search(str(logdata['rule']['name']))
        logdata['ThreatPurpose'] = m['ThreatPurpose']
        logdata['ResourceTypeAffected'] = m['ResourceTypeAffected']
        logdata['ThreatFamilyName'] = m['ThreatFamilyName']

        action_type = (logdata['ProductFields']
                       ['aws/guardduty/service/action/actionType'])
        if 'NETWORK_CONNECTION' in action_type:
            direction_key = ('aws/guardduty/service/action/'
                             'networkConnectionAction/connectionDirection')
            direction = logdata['ProductFields'][direction_key].lower()
        elif 'DNS_REQUEST' in action_type:
            direction = "outbound"
        else:
            direction = "inbound"
        if 'network' in logdata:
            logdata['network']['direction'] = direction
        else:
            logdata['network'] = {'direction': direction}
        if "outbound" in direction:
            logdata['source'], logdata['destination'] = (
                logdata.get('destination'), logdata.get('source'))
            if not logdata['source']:
                del logdata['source']
            if not logdata['destination']:
                del logdata['destination']
        # event.category
        if logdata['ThreatPurpose'] in ('Backdoor', 'CryptoCurrency',
                                        'Trojan'):
            logdata['event']['category'] = 'malware'
    elif 'iam access analyzer' in module:
        pass
    elif 'security hub' in module:
        logdata['__doc_id_suffix'] = int(
            datetime.fromisoformat(logdata['@timestamp']).timestamp())
        logdata['rule']['name'] = logdata['Title']
    elif 'inspector' in module:
        logdata['event']['category'] = 'package'
    elif 'macie' in module:
        logdata['event']['category'] = 'intrusion_detection'
        logdata['rule']['name'] = logdata['Title']

    resouce_dict = get_values_from_asff_resources(logdata['Resources'])
    logdata = utils.merge_dicts(logdata, resouce_dict)

    return logdata
