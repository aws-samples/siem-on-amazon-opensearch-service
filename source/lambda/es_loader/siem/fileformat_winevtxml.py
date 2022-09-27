# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.8.0c'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import csv
import os
import re
import xml
from functools import cached_property, lru_cache

import xmltodict
from aws_lambda_powertools import Logger

from siem import FileFormatBase

logger = Logger(child=True)

re_firstword = re.compile(r'<Event xmlns=')
re_lastword = re.compile(r'</Event>$')

eventidfile = f'{os.path.dirname(__file__)}/fileformat_winevtxml_eventid.tsv'
with open(eventidfile, 'rt') as fp:
    event_id_dict = {}
    reader = csv.DictReader(
        filter(lambda row: row[0] != '#', fp), delimiter='\t')
    for row_dict in reader:
        event_id_dict[row_dict['event_id']] = row_dict


@lru_cache(maxsize=100000)
def lookup_event_id(event_id, key):
    if event_id in event_id_dict:
        return event_id_dict[event_id].get(key, None)
    return None


def initial_extract_action_outcome(logdata):
    win_dict = {'event': {}}
    try:
        event_id = logdata['Event']['System']['EventID']
    except KeyError:
        return win_dict
    action = lookup_event_id(event_id, 'action')
    if action:
        win_dict['event']['action'] = action
    outcome = lookup_event_id(event_id, 'outcome')
    if outcome:
        win_dict['event']['outcome'] = outcome
    return win_dict


class FileFormatWinEvtXml(FileFormatBase):

    @cached_property
    def log_count(self):
        count = 0
        for line in self.rawdata:
            if re_firstword.match(line):
                count += 1
        return count

    def extract_log(self, start, end, logmeta={}):
        count = 0
        multilog = []
        is_in_scope = False
        for line in self.rawdata:
            first_match = re_firstword.match(line)
            if first_match:
                count += 1
                if start <= count <= end:
                    is_in_scope = True
                elif count > end:
                    break
                else:
                    continue
            elif not is_in_scope:
                continue
            last_match = re_lastword.search(line)
            if first_match and last_match:
                # it means one line. not multiline
                logdict = self.convert_lograw_to_dict(line)
                yield(line, logdict, logmeta)
                is_in_scope = False
            elif first_match:
                multilog.append(line)
            elif last_match:
                multilog.append(line)
                lograw = "".join(multilog)
                logdict = self.convert_lograw_to_dict(lograw)
                yield(lograw, logdict, logmeta)
                is_in_scope = False
                multilog = []
            elif is_in_scope:
                multilog.append(line)

    def convert_lograw_to_dict(self, lograw, logconfig=None):
        logdict = {}

        lograw = lograw.strip().rstrip("\u0000")
        try:
            logdict = self._parse(lograw)
        except xml.parsers.expat.ExpatError:
            # delete control character
            lograw = lograw.translate(dict.fromkeys(range(32)))
            logdict = self._parse(lograw)

        logdict['Event'].pop('#text', None)
        logdict['Event']['System'].pop('#text', None)
        try:
            data_list = logdict['Event']['EventData']['Data']
            logdict['Event']['EventData'].pop('#text', None)
        except (KeyError, NameError, TypeError):
            data_list = None
        if data_list:
            data_dict = {}
            for data in data_list:
                if isinstance(data, dict) and '#text' in data:
                    temp = data['#text']
                    if temp != '-':
                        data_dict[data['Name']] = data['#text']
            logdict['Event']['EventData']['Data'] = data_dict

        try:
            logdict['Event']['System']['EventID']
        except KeyError:
            return logdict
        if isinstance(logdict['Event']['System']['EventID'], dict):
            Qualifiers = logdict['Event']['System']['EventID']['Qualifiers']
            logdict['Event']['System']['EventID'] = (
                logdict['Event']['System']['EventID']['#text'])
            logdict['Event']['System']['Qualifiers'] = Qualifiers

        try:
            logdict['Event']['EventData']['Data']['AccessList'] = (
                logdict['Event']['EventData']['Data']['AccessList'].split())
        except (TypeError, KeyError):
            pass

        try:
            logdict['Event']['EventData']['Data']['PrivilegeList'] = (
                (logdict['Event']['EventData']['Data']
                 ['PrivilegeList'].split()))
        except (TypeError, KeyError):
            pass

        return logdict

    def _parse(self, lograw):
        logdict = xmltodict.parse(
            lograw, strip_whitespace=None, attr_prefix='')
        return logdict
