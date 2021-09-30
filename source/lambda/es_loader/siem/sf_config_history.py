# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from siem.sf_config_snapshot import (convert_dict_to_list, extract_host,
                                     extract_ip, extract_user,
                                     rename_config_field_name, update_doc_ids)


def transform(logdata):
    logdata = update_doc_ids(logdata)
    logdata = convert_dict_to_list(logdata)
    logdata = rename_config_field_name(logdata)
    logdata = extract_host(logdata)
    logdata = extract_user(logdata)
    logdata = extract_ip(logdata)

    return logdata
