import json
import re
from siem import utils


def str_camel_to_snake(camel_case_str):
    """camel case の文字列を snake case へ変換する関数

    Args:
        camel_case_str (str): camel case の文字列

    Returns:
        str: snake case の文字列
    """
    if camel_case_str is None:
        return None
    else:
        pattern = r'([a-z|0-9])([A-Z])'
        def callback(x): return x.group(1) + '_' + x.group(2).lower()
        snake_case_str = re.sub(pattern, callback, camel_case_str)
        return snake_case_str


def dict_camel_to_snake(target):
    """辞書のキー名を camel case から snake case へ変換する関数

    Args:
        target (dict): キー名が camel case な dict

    Returns:
        dict: キー名が snake case な dict
    """
    if isinstance(target, dict):
        # .keys() のループ中に辞書へ変更を加えるとエラーとなるためリストへ変換
        for key in list(target.keys()):
            snake_key = str_camel_to_snake(key)
            if snake_key != key:
                target[snake_key] = target[key]
                del target[key]
                key = snake_key
            if isinstance(target[key], dict):
                dict_camel_to_snake(target[key])
        return target
    else:
        return str_camel_to_snake(target)


def set_prefix(input_dict, key_name, prefix_name):
    """辞書に対して Prefix を付与する関数

    Args:
        input_dict (dict): Prefix を付けたいフィールドが格納されている元の辞書
        key_name (str): Prefix 直下のフィールド名
        prefix_name (str): 対象の辞書へ付与する Prefix

    Returns:
        dict: Prefix 付きの辞書
            形式：{prefix_name : input_dict[key_name]}
    """
    output_dict = {
        prefix_name: {key_name: dict_camel_to_snake(input_dict)}}
    return output_dict


def transform(logdata):
    # event.outcome フィールドへ情報を投入
    if logdata.get('outcome'):
        if logdata.get('outcome', {}).get('result'):
            outcome = logdata['outcome']['result'].lower()
            if outcome == 'success' or outcome == 'allow':
                logdata['event']['outcome'] = 'success'
            elif outcome == 'failure' or outcome == 'deny':
                logdata['event']['outcome'] = 'failure'
            else:
                logdata['event']['outcome'] = 'unknown'

    # User name や email などのユーザー関連の情報を ECS フィールドとしてマッピング
    if logdata.get('actor', {}).get('type'):
        if logdata['actor']['type'] == 'User':
            q = r"^(?P<name>.*)@(?P<domain>.*)$"
            n = re.match(q, logdata['actor']['alternateId'])
            if n:
                name_domain_new_dict = {
                    'user': {'domain': n.group('domain'), 'name':  n.group('name'), 'email': logdata['actor']['alternateId']}}
                utils.merge_dicts(logdata, name_domain_new_dict)
            user_new_dict = {
                'client': {'user': {'full_name': logdata['actor']['displayName'], 'id': logdata['actor']['id']}},
                'source': {'user': {'full_name': logdata['actor']['displayName'], 'id': logdata['actor']['id']}},
                'related': {'user': logdata['actor']['displayName']}}
            utils.merge_dicts(logdata, user_new_dict)

    # 独自フィールドに対して Prefix を付与
    # Okta 独自のフィールドと他ログのフィールドで Type のコンフリクト等が発生するのを防ぐ

    # logdata 直下にある Okta 独自フィールド名
    # フィールド名が camel case のものは snake case へ変換する
    okta_fields = ['actor', 'debugContext',
                   'request', 'outcome', 'transaction', 'authenticationContext', 'securityContext', 'displayMessage',
                   'uuid', 'version', 'severity', 'published', 'legacyEventType', 'eventType']
    for field in okta_fields:
        if logdata.get(field):
            snake_field_name = str_camel_to_snake(field)
            tmp_okta_dict = set_prefix(
                logdata[field], snake_field_name, 'okta')
            utils.merge_dicts(logdata, tmp_okta_dict)
            del logdata[field]

    # target フィールドは独自フィールドだが中身が配列となっている場合があるため別処理
    if logdata.get('target'):
        target_new_dict = {'okta': {'target': [logdata.get('target')]}}
        utils.merge_dicts(logdata, target_new_dict)

        for key in logdata['target']:
            if key['type'] == 'AppInstance':
                app_new_dict = {
                    'okta': {'target': {
                        'app_name': {
                            'alternate_id': key['alternateId'],
                            'display_name': key['displayName']
                        }}}}
                utils.merge_dicts(logdata, app_new_dict)

    # Client フィールドは ECS も混ざっているため、一つずつ対応
    tmp_okta_client_dict = {'okta': {
        'client': {
            'device': logdata['client']['device'],
            'ip': logdata['client']['ipAddress'],
            'user_agent': dict_camel_to_snake(logdata['client']['userAgent']),
            'id': logdata['client']['id'],
            'zone': logdata['client']['zone']
        }}}
    utils.merge_dicts(logdata, tmp_okta_client_dict)

    # 不要な独自フィールドを削除
    del logdata['target']
    del logdata['client']['device']
    del logdata['client']['ipAddress']
    del logdata['client']['userAgent']
    del logdata['client']['geographicalContext']
    del logdata['client']['id']
    del logdata['client']['zone']

    return logdata
