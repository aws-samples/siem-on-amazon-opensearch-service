# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.8.0c'
__license__ = 'MIT-0'
__author__ = 'Katsuya Matsuoka'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import ipaddress


def get_arn_from_metadata(check_metadata, result_metadata):
    service = ''
    arn = ''
    if 'Service' in check_metadata:
        service_pos = check_metadata.index('Service')
        service = result_metadata[service_pos].lower()
    if 'Resource' in check_metadata:
        arn_pos = check_metadata.index('Resource')
        arn = result_metadata[arn_pos]
    if 'Workload ARN' in check_metadata:
        arn_pos = check_metadata.index('Workload ARN')
        arn = result_metadata[arn_pos]
    arn_list = arn.split(':')
    if len(arn_list) > 2:
        service = arn_list[2].lower()
    return service, arn_list


def transform(logdata):
    # Update event.kind based on result.status (default event.kind: event)
    if logdata['result']['status'] in ['warning', 'error']:
        logdata['event']['kind'] = 'alert'

    # Result contains multiple resources results
    if 'flaggedResource' in logdata['result']:
        # Update event.kind based on result.flaggedResource.status
        flagged_resource = logdata['result']['flaggedResource']
        if flagged_resource['status'] in ['warning', 'error']:
            logdata['event']['kind'] = 'alert'
        else:
            logdata['event']['kind'] = 'event'

        if 'metadata' in flagged_resource:
            service = 'trustedadvisor'
            result_metadata = flagged_resource['metadata']
            if 'metadata' in logdata['check']:
                check_metadata = logdata['check']['metadata']
                service, arn_list = get_arn_from_metadata(
                    check_metadata, result_metadata)

            # Update cloud.service.name
            logdata['cloud']['service'] = {}
            logdata['cloud']['service']['name'] = service

            # Update cloud.instance.id and cloud.service.name
            # when service is ec2 and arn contains resource type and id
            if len(arn_list) > 5 and service == 'ec2':
                # Extract list of resource-type and resource-id
                # [resource-type, resource-id] as resource_type_id when arn is
                # arn:partition:service:region:account-id:resource-type/resource-id
                resource_type_id = arn_list[5].split('/')
                if len(resource_type_id) > 1:
                    service = resource_type_id[0]
                    if service == 'instance':
                        service = 'ec2'
                        logdata['cloud']['instance'] = {}
                        logdata['cloud']['instance']['id'] = \
                            resource_type_id[1]
                    logdata['cloud']['service']['name'] = service

            # Update event.category (default: configuration)
            if service in ['rds', 'dynamodb', 's3',
                           'ebs', 'redshift', 'elasticache']:
                logdata['event']['category'] = 'database'
            elif service in ['iam', 'cloudtrail']:
                logdata['event']['category'] = 'iam'
            elif service in ['vpc', 'route53', 'elasticloadbalancing',
                             'network-acl', 'subnet', 'secuirty-group']:
                logdata['event']['category'] = 'network'

            # related.*
            logdata['related'] = {}
            for item in flagged_resource['metadata']:
                try:
                    ipaddress.ip_address(item)
                except ValueError:
                    continue
                logdata['related']['ip'] = [item]
            instance_id = logdata['cloud'].get('instance', {}).get('id')
            if instance_id:
                logdata['related']['hosts'] = [instance_id]

    return logdata
