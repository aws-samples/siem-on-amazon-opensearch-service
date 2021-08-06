# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import csv
import os
import re
import xml
from functools import lru_cache

import xmltodict

re_firstword = re.compile(r'<Event xmlns=')
re_lastword = re.compile(r'</Event>$')

with open(f'{os.path.dirname(__file__)}/winevtxml_eventid.tsv') as f:
    event_id_dict = {}
    reader = csv.DictReader(f, delimiter='\t')
    for row_dict in reader:
        event_id_dict[row_dict['event_id']] = row_dict


@lru_cache(maxsize=100000)
def lookup_event_id(event_id, key):
    if event_id in event_id_dict:
        return event_id_dict[event_id].get(key, None)
    return None


def initial_extract_action_outcome(logdata):
    win_dict = {'event': {}}
    if 'EvnetID' not in logdata['Event']['System']:
        return win_dict
    event_id = logdata['Event']['System']['EventID']
    action = lookup_event_id(event_id, 'action')
    if action:
        win_dict['event']['action'] = action
    outcome = lookup_event_id(event_id, 'outcome')
    if outcome:
        win_dict['event']['outcome'] = outcome
    return win_dict


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

        last_match = re_lastword.search(line)
        if first_match and last_match:
            # it means one line. not multiline
            yield(line, metadata)
        elif first_match:
            multilog.append(line)
            is_in_scope = True
        elif last_match:
            multilog.append(line)
            yield("".join(multilog), metadata)
            is_in_scope = False
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
                temp = data['#text']
                if temp != '-':
                    data_dict[data['Name']] = data['#text']
        logdata_dict['Event']['EventData']['Data'] = data_dict

    try:
        logdata_dict['Event']['System']['EventID']
    except KeyError:
        return logdata_dict
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
            (logdata_dict['Event']['EventData']['Data']
             ['PrivilegeList'].split()))
    except (TypeError, KeyError):
        pass

    return logdata_dict
