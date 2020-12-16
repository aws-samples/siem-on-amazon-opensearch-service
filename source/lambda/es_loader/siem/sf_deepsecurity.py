import re
import base64
import json
import ipaddress
from siem import merge, put_value_into_dict, get_value_from_dict

def transform(logdata):
    # https://cloudone.trendmicro.com/docs/workload-security/event-syslog-message-formats/
    fields = logdata['message'].split('|')
    if len(fields) < 8:
        print("Illegal format")
        return Null
    logdata.setdefault('agent', {})
    logdata['agent']['name'] = " ".join([fields[1],fields[2],fields[3]])
    logdata.setdefault('rule', {})
    logdata['rule']['name'] = " ".join([fields[4],fields[5]])
    logdata.setdefault('event', {})
    logdata['event']['severity'] = fields[6]
    
    # \\=を適当な文字列に置換しておく
    message = re.sub('\\\\=', '____', fields[7])
    # =をdelimiterとして、順に処理していく
    attributes = message.split('=')
    next_ptr = attributes.pop(0)
    for ptr in attributes:
        values = ptr.split()
        if values is None:
            break
        curr_ptr = next_ptr
        next_ptr = values.pop()
        value = ' '.join(values)
        if value:
            logdata[curr_ptr] = re.sub('____', '=', value)
    # 末尾の処理
    logdata[curr_ptr] = re.sub('____', '=', value + next_ptr)

    if 'act' in logdata:
        # IDS:Resetは、alert出力のみでpacket dropを行わない
        # 誤解を招くので、置換しておく
        logdata['act'] = re.sub("IDS:Reset","DetectOnly:NotReset",logdata['act'])

    # 以下はecsにmappingしていく処理
    deepsecurity_ecs_keys = {
        'destination.ip': 'dst',
        'destination.port': 'dpt',
        'destination.mac': 'dmac',
        'destination.bytes': 'out',
        'source.ip': 'src',
        'source.port': 'spt',
        'source.mac': 'smac',
        'source.bytes': 'in',
        'network.transport': 'proto',
        'event.action': 'act',
        'server.name': 'fluent_hostname',
        'file.path': 'fname',
        'event.count': 'cnt',
        'rule.category': 'cs1',
        'host.id': 'cn1',
        'event.original': 'msg',
    }

    for ecs_key in deepsecurity_ecs_keys:
        original_keys = deepsecurity_ecs_keys[ecs_key]
        v = get_value_from_dict(logdata, original_keys)
        if v:
            new_ecs_dict = put_value_into_dict(ecs_key, v)
            if ".ip" in ecs_key:
                try:
                    ipaddress.ip_address(v)
                except ValueError:
                    continue
            merge(logdata, new_ecs_dict)
            del logdata[original_keys]

    # source.ipが設定されていなければ、dvcで代用する
    if "dvc" in logdata:
        if "source" in logdata and not "ip" in logdata['source']:
            logdata['source']['ip'] = logdata['dvc']
        else:
            logdata['source'] = { 'ip': logdata['dvc'] }

    # packet captureをdecodeしておく
    if 'TrendMicroDsPacketData' in logdata:
        saved = logdata['TrendMicroDsPacketData']
        try:
            logdata['TrendMicroDsPacketData'] = base64.b64decode(logdata['TrendMicroDsPacketData']).decode("utf-8", errors="backslashreplace")
        except Exception as e:
            print(e)
            logdata['TrendMicroDsPacketData'] = saved
        # filter out 'cookie'
        filtered = []
        for line in logdata['TrendMicroDsPacketData'].split("\n"):
            if re.findall(r'^cookie',line.lower()):
                continue
            filtered.append(line)
        logdata['TrendMicroDsPacketData'] = "\n".join(filtered)
        # X-Forwarded-Forを取り出す X-Forwarded-For: 123.123.123.234
        m = re.search(r'X-Forwarded-For: ([0-9.]+)', logdata['TrendMicroDsPacketData'])
        if m:
            logdata['source']['ip'] = m.group(1)

    del logdata['TrendMicroDsTenant'], logdata['TrendMicroDsTenantId']

    return logdata
