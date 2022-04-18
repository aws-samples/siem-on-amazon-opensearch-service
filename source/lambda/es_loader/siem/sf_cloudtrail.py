# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.7.0-rc.1'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'


def convert_text_into_dict(temp_value):
    if isinstance(temp_value, str):
        return {'value': temp_value}
    else:
        return temp_value


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

    # https://github.com/aws-samples/siem-on-amazon-elasticsearch/issues/33
    try:
        response_cred = logdata['responseElements']['credentials']
    except (KeyError, TypeError):
        response_cred = None
    if isinstance(response_cred, str):
        logdata['responseElements']['credentials'] = {}
        if 'arn:aws:iam' in response_cred:
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

    return logdata
