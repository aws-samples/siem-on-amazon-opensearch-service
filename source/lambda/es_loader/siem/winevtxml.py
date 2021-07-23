import xml

import xmltodict


def parse(logdata):
    logdata_dict = xmltodict.parse(
        logdata,
        strip_whitespace=None,
        attr_prefix='',
    )
    return logdata_dict


def to_dict(logdata):
    logdata_dict = {}
    logdata = logdata.strip().rstrip("\u0000")
    try:
        logdata_dict = parse(logdata)
    except xml.parsers.expat.ExpatError:
        # delete control character
        logdata = logdata.translate(dict.fromkeys(range(32)))
        logdata_dict = parse(logdata)

    try:
        data_list = logdata_dict['Event']['EventData']['Data']
    except (KeyError, NameError, TypeError):
        data_list = None
    if data_list:
        data_dict = {}
        for data in data_list:
            if isinstance(data, dict) and '#text' in data:
                data_dict[data['Name']] = data['#text']
        logdata_dict['Event']['EventData']['Data'] = data_dict

    if isinstance(logdata_dict['Event']['System']['EventID'], dict):
        Qualifiers = logdata_dict['Event']['System']['EventID']['Qualifiers']
        logdata_dict['Event']['System']['EventID'] = (
            logdata_dict['Event']['System']['EventID']['#text'])
        logdata_dict['Event']['System']['Qualifiers'] = Qualifiers

    return logdata_dict
