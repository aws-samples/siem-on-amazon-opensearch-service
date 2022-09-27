# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.8.0c'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'


def convert_text_into_dict(temp_value):
    if isinstance(temp_value, str):
        return {'value': temp_value}
    else:
        return temp_value


def extract_instance_id(logdata):
    event_source = logdata.get('eventSource', '')
    event_name = logdata.get('eventName', '')
    instance_id = None
    if event_source == 'ssm.amazonaws.com':
        if event_name in ('StartSession', 'GetConnectionStatus'):
            instance_id = logdata.get('requestParameters', {}).get('target')
    elif event_source in ('sts.amazonaws.com'):
        if logdata.get('userAgent') == 'ec2.amazonaws.com':
            instance_id = logdata.get(
                'requestParameters', {}).get('roleSessionName')

    elif event_source in ('cloudhsm.amazonaws.com'):
        logdata['related'] = {'hosts': []}
        try:
            cluster_id = logdata.get('requestParameters', {}).get('clusterId')
        except Exception:
            cluster_id = None
        if cluster_id:
            logdata['related']['hosts'].append(cluster_id)
        try:
            hsm_id = logdata['responseElements']['hsmId']
        except Exception:
            try:
                hsm_id = logdata['responseElements']['hsm']['hsmId']
            except Exception:
                hsm_id = None
        if hsm_id:
            logdata['cloud']['instance'] = {'id': hsm_id}
            logdata['related']['hosts'].append(hsm_id)

    if instance_id:
        logdata['cloud']['instance'] = {'id': instance_id}
    return logdata


def transform(logdata):
    if 'errorCode' in logdata or 'errorMessage' in logdata:
        logdata['event']['outcome'] = 'failure'
    else:
        logdata['event']['outcome'] = 'success'
    try:
        name = logdata['user']['name']
        if ':' in name:
            logdata['user']['name'] = name.split(':')[-1].split('/')[-1]
    except KeyError:
        pass
    logdata = extract_instance_id(logdata)

    # https://github.com/aws-samples/siem-on-amazon-elasticsearch/issues/33
    try:
        response_cred = logdata['responseElements']['credentials']
    except (KeyError, TypeError):
        response_cred = None
    if isinstance(response_cred, str):
        logdata['responseElements']['credentials'] = {}
        if 'arn:aws:iam' in response_cred:
            logdata['responseElements']['credentials']['iam'] = response_cred
        elif 'arn:aws-cn:iam' in response_cred:
            logdata['responseElements']['credentials']['iam'] = response_cred
        elif 'arn:aws-us-gov:iam' in response_cred:
            logdata['responseElements']['credentials']['iam'] = response_cred
        else:
            logdata['responseElements']['credentials']['value'] = response_cred

    # https://github.com/aws-samples/siem-on-amazon-elasticsearch/issues/108
    try:
        logdata['requestParameters']['tags'] = convert_text_into_dict(
            logdata['requestParameters']['tags'])
    except (KeyError, TypeError):
        pass

    # https://github.com/aws-samples/siem-on-amazon-elasticsearch/issues/114
    try:
        logdata['responseElements']['policy'] = convert_text_into_dict(
            logdata['responseElements']['policy'])
    except (KeyError, TypeError):
        pass

    # https://github.com/aws-samples/siem-on-amazon-elasticsearch/issues/139
    try:
        logdata['requestParameters']['disableApiTermination'] = (
            logdata['requestParameters']['disableApiTermination']['value'])
    except (KeyError, TypeError):
        pass

    # https://github.com/aws-samples/siem-on-amazon-elasticsearch/issues/242
    try:
        status = logdata['responseElements']['status']
    except (KeyError, TypeError):
        status = None
    if status and isinstance(status, str):
        logdata['responseElements']['status'] = {'status': status}

    event_source = logdata.get('eventSource', None)
    if not event_source:
        pass
    elif event_source == 'athena.amazonaws.com':
        # #153
        try:
            tableMetadataList = (
                logdata['responseElements']['tableMetadataList'])
        except (KeyError, TypeError):
            tableMetadataList = None
        if tableMetadataList:
            for tableMetadata in tableMetadataList:
                old_field = 'projection.date.interval.unit'
                new_field = 'projection.date.interval_unit'
                try:
                    tableMetadata['parameters'][new_field] = (
                        tableMetadata['parameters'].pop(old_field))
                except KeyError:
                    pass
        try:
            partableMetadata = (
                logdata['responseElements']['tableMetadata'])
        except (KeyError, TypeError):
            partableMetadata = None
        if partableMetadata:
            old_field = 'projection.part_date.interval.unit'
            new_field = 'projection.part_date.interval_unit'
            try:
                partableMetadata['parameters'][new_field] = (
                    partableMetadata['parameters'].pop(old_field))
            except KeyError:
                pass

    elif event_source == 'glue.amazonaws.com':
        # #156, #166
        try:
            configuration = logdata['requestParameters']['configuration']
        except (KeyError, TypeError):
            configuration = None
        if configuration and isinstance(configuration, str):
            logdata['requestParameters']['configuration'] = {
                'text': configuration}
    elif event_source == 'cognito-idp.amazonaws.com':
        # #163
        try:
            session = logdata['responseElements']['session']
        except (KeyError, TypeError):
            session = None
        if session and isinstance(session, str):
            logdata['responseElements']['session'] = {'value': session}
    elif event_source == 'ecs.amazonaws.com':
        # #167
        try:
            command = logdata['requestParameters']['command']
        except (KeyError, TypeError):
            command = None
        if command and isinstance(command, str):
            logdata['requestParameters']['command'] = {'command': command}
    elif event_source in ('ssm.amazonaws.com'):
        try:
            params = logdata['requestParameters']['parameters']
        except (KeyError, TypeError):
            params = None
        if params and isinstance(params, str):
            logdata['requestParameters']['parameters'] = {'value': params}
    elif event_source in ('redshift-data.amazonaws.com'):
        try:
            db = logdata['responseElements']['database']
        except (KeyError, TypeError):
            db = None
        if db and isinstance(db, str):
            logdata['responseElements']['database'] = {'name': db}
    elif event_source in ('cloud9.amazonaws.com'):
        try:
            settings = logdata['requestParameters']['settings']
        except (KeyError, TypeError):
            settings = None
        if settings and isinstance(settings, str):
            logdata['requestParameters']['settings'] = {'value': settings}
    elif event_source in ('s3.amazonaws.com'):
        try:
            rules = (logdata['requestParameters']['ReplicationConfiguration']
                     ['Rule'])
        except (KeyError, TypeError):
            rules = None
        if rules and isinstance(rules, list):
            for i, rule in enumerate(rules):
                if rule.get('Filter'):
                    rules[i]['Filter'] = str(rule['Filter'])
    elif event_source in ('inspector2.amazonaws.com'):
        try:
            ids = logdata['requestParameters']['accountIds']
        except (KeyError, TypeError):
            ids = None
        if ids and isinstance(ids, list) and isinstance(ids[0], dict):
            logdata['requestParameters']['accountIds'] = str(ids)

    return logdata
