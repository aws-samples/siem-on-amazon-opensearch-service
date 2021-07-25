# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import re
import xml

import xmltodict

re_firstword = re.compile(r'<Event xmlns=')
re_endword = re.compile(r'.*</Event>$')


def count_event(rawdata):
    count = 0
    for line in rawdata:
        if re_firstword.match(line):
            count += 1
    return count


def extract_event(rawdata, start=0, end=0):
    count = 0
    metadata = {}
    multilog = []
    is_in_scope = False
    for line in rawdata:
        first_match = re_firstword.match(line)
        if first_match:
            count += 1
            if not start < count <= end:
                continue

        end_match = re_endword.match(line)
        if first_match and end_match:
            # it means one line. not multiline
            yield(line.rstrip(), metadata)
        elif first_match:
            multilog.append(line)
            is_in_scope = True
        elif end_match:
            multilog.append(line)
            yield("".join(multilog).rstrip(), metadata)
            multilog = []
        elif is_in_scope:
            multilog.append(line)


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

    logdata_dict['Event'].pop('#text', None)
    logdata_dict['Event']['System'].pop('#text', None)
    try:
        data_list = logdata_dict['Event']['EventData']['Data']
        logdata_dict['Event']['EventData'].pop('#text', None)
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

    try:
        logdata_dict['Event']['EventData']['Data']['AccessList'] = (
            logdata_dict['Event']['EventData']['Data']['AccessList'].split())
    except (TypeError, KeyError):
        pass

    try:
        logdata_dict['Event']['EventData']['Data']['PrivilegeList'] = (
            logdata_dict['Event']['EventData']['Data']['PrivilegeList'].split())
    except (TypeError, KeyError):
        pass

    return logdata_dict
