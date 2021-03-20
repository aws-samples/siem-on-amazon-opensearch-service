# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from siem import utils


def transform(logdata):
    identifier = utils.cluster_instance_identifier(logdata)
    logdata['rds']['cluster_identifier'] = identifier['cluster']
    logdata['rds']['instance_identifier'] = identifier['instance']

    logdata = utils.convert_underscore_field_into_dot_notation(
        'mysql', logdata)
    return logdata
