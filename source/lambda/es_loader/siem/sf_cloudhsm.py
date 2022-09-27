# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.8.0c'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'


def extract_cluster_instance(logdata):
    cluster_id = None
    hsm_id = None
    if logdata.get('@log_group'):
        cluster_id = logdata.get('@log_group').split('/')[3]
    if logdata.get('@log_stream'):
        hsm_id = logdata.get('@log_stream')
    return cluster_id, hsm_id


def transform_hsm(logdata, cluster_id, hsm_id):
    logdata['cloudhsm'] = {}
    logdata['related'] = {'hosts': []}
    try:
        logdata['@id'] = (f"{hsm_id}{logdata['sequence_no']}"
                          f"{logdata['timestamp_usec']}")
    except Exception:
        pass
    if logdata.get('opcode_v2'):
        logdata['opcode'] = logdata.pop('opcode_v2')
        logdata['opcode_hex'] = logdata.pop('opcode_hex_v2')
    if logdata.get('priv_secret_key_handle_v2'):
        logdata['priv_secret_key_handle'] = logdata.pop(
            'priv_secret_key_handle_v2')
    if cluster_id:
        logdata['cloudhsm']['cluster_id'] = cluster_id
        logdata['related']['hosts'].append(cluster_id)
    if hsm_id:
        logdata['cloudhsm']['hsm_id'] = hsm_id
        logdata['cloud']['instance'] = {'id': hsm_id}
        logdata['related']['hosts'].append(hsm_id)
    logdata['sequence_no'] = int(logdata['sequence_no'], 16)
    logdata['reboot_counter'] = int(logdata['reboot_counter'], 16)

    # user
    if (logdata['command_type'] == 'CN_MGMT_CMD') and ('user' not in logdata):
        logdata['user'] = {}
    if logdata['opcode'] in ('CN_LOGIN', 'CN_LOGOUT', 'CN_APP_FINALIZE',
                             'CN_CLOSE_SESSION'):
        logdata['user']['name'] = logdata['user_name']
        logdata['user']['roles'] = logdata['user_type']
    elif logdata['opcode'] in (
            'CN_CREATE_USER', 'CN_CREATE_CO', 'CN_CREATE_APPLIANCE_USER',
            'CN_DELETE_USER', 'CN_SET_M_VALUE', 'CN_CHANGE_PSWD',
            'CN_APPROVE_TOKEN'):
        user_name = logdata['target_user_name']
        if not user_name:
            user_name = logdata['user_name']
        user_type = logdata['target_user_type']
        if not user_type:
            user_type = logdata['user_type']
        user_id = logdata['target_user_id']
        logdata['user']['target'] = {
            'name': user_name, 'roles': user_type, 'id': user_id}

    if logdata.get('hsm_return'):
        logdata['event']['outcome'] = 'success'
    else:
        logdata['event']['outcome'] = 'failure'

    return logdata


def transform(logdata):
    cluster_id, hsm_id = extract_cluster_instance(logdata)
    logdata = transform_hsm(logdata, cluster_id, hsm_id)
    return logdata
