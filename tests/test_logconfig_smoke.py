# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Smoke tests: every log type in aws.ini builds a logconfig and loads."""
from types import SimpleNamespace

import pytest

from siem import utils

FILE_FORMATS = ('json', 'csv', 'text', 'multiline', 'parquet', 'cef',
                'winevtxml', 'xml')


def _logtypes(etl_config):
    return [s for s in etl_config.sections() if s != 'index-metrics']


# aws.ini is parsed at collection time so each log type is its own test id
ALL_LOGTYPES = _logtypes(utils.get_etl_config())


def test_aws_ini_has_logtypes(etl_config):
    assert len(_logtypes(etl_config)) >= 40


def test_every_logtype_builds_logconfig(etl_config, create_logconfig):
    for logtype in _logtypes(etl_config):
        logconfig = create_logconfig(logtype)
        assert logconfig['index_name'], logtype


def test_s3key_dict_covers_logtypes(etl_config, logtype_s3key_dict):
    assert logtype_s3key_dict


@pytest.mark.parametrize('logtype', ['cloudtrail', 'vpcflowlogs', 'guardduty'])
def test_core_logtypes_present(etl_config, logtype):
    assert logtype in etl_config.sections()
    assert utils is not None


@pytest.mark.parametrize('logtype', ALL_LOGTYPES)
def test_logtype_logconfig(create_logconfig, logtype):
    logconfig = create_logconfig(logtype)
    assert logconfig['index_name'], logtype
    assert logconfig['file_format'] in FILE_FORMATS, logtype
    assert isinstance(logconfig['via_cwl'], bool)
    assert isinstance(logconfig['ecs'], list)


@pytest.mark.parametrize('logtype', ALL_LOGTYPES)
def test_logtype_sf_module_imports(create_logconfig, logtype):
    """script_ecs = True requires siem/sf_<logtype>.py to import cleanly"""
    logconfig = create_logconfig(logtype)
    logfile = SimpleNamespace(logtype=logtype)
    sf_module = utils.load_sf_module(logfile, logconfig, [])
    if logconfig['script_ecs']:
        assert callable(getattr(sf_module, 'transform', None)), logtype
    else:
        assert sf_module is None
