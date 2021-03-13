# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

def transform(logdata):
    action = logdata['event']['action']
    if 'ACCEPT' in action:
        logdata['event']['outcome'] = 'success'
    elif 'REJECT' in action:
        logdata['event']['outcome'] = 'failure'
    else:
        logdata['event']['outcome'] = 'unknown'

    if logdata['protocol'] == "6":
        logdata['network']['transport'] = 'tcp'
    elif logdata['protocol'] == "17":
        logdata['network']['transport'] = 'udp'
    elif logdata['protocol'] == "1":
        logdata['network']['transport'] = 'icmp'
    elif logdata['protocol'] == "41":
        logdata['network']['transport'] = 'ipv6'
    elif logdata['protocol'] == "8":
        logdata['network']['transport'] = 'egp'
    elif logdata['protocol'] == "33":
        logdata['network']['transport'] = 'dccp'
    elif logdata['protocol'] == "42":
        logdata['network']['transport'] = 'sdrp'
    elif logdata['protocol'] == "47":
        logdata['network']['transport'] = 'gre'
    elif logdata['protocol'] == "132":
        logdata['network']['transport'] = 'sctp'

    try:
        logdata['network']['type'] = logdata['network']['type'].lower()
    except KeyError:
        pass

    return logdata
