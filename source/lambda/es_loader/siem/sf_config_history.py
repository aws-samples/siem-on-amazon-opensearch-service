# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.8.0c'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

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
