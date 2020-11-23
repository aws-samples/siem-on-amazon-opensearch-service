# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import re
import siem

RE_GDTYPE = re.compile(r"/(?P<ThreatPurpose>\w*):(?P<ResourceTypeAffected>\w*)"
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
        elif resouce['Type'] == 'AwsS3Bucket':
            pass
    return resouce_dict


def transform(logdata):
    # event (ecs)
    module = (logdata['ProductFields']['aws/securityhub/ProductName']).lower()
    logdata['event']['module'] = module

    if 'guardduty' in module:
        logdata['event']['category'] = 'intrusion_detection'

        m = RE_GDTYPE.search(logdata['rule']['name'])
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

        resouce_dict = get_values_from_asff_resources(logdata['Resources'])
        siem.merge(logdata, resouce_dict)
    elif 'iam access analyzer' in module:
        pass
    elif 'security hub' in module:
        pass
    elif 'inspector' in module:
        logdata['event']['category'] = 'package'
        # instanceid = siem.re_instanceid.search(logdata['Title'])
        # if instanceid:
        #     logdata['cloud']['instance'] = {'id': instanceid.group(1)}
    elif 'macie' in module:
        logdata['event']['category'] = 'intrusion_detection'

    return logdata
