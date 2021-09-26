# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import datetime
import hashlib

from siem.sf_config_snapshot import (convert_dict_to_list,
                                     rename_config_field_name)


def transform(logdata):
    doc_id_seed = logdata['awsAccountId'] + logdata['awsRegion'] \
        + logdata['resourceType'] + logdata['resourceId']
    logdata['@id'] = hashlib.md5(doc_id_seed.encode()).hexdigest()

    pubdate = datetime.datetime.fromisoformat(logdata['@timestamp'])
    logdata['__doc_id_suffix'] = (
        f'{pubdate.year}{pubdate.month}{pubdate.day}'
        f'T{pubdate.hour}{pubdate.minute}{pubdate.second}')

    logdata = convert_dict_to_list(logdata)
    logdata = rename_config_field_name(logdata)

    return logdata
