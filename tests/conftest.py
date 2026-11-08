# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Shared fixtures for es-loader unit tests.

es_loader/index.py connects to OpenSearch at import time, so the
functions that build logconfig are extracted with ast and executed here.
"""
import ast
import gzip
import io
import json
import os
import re
import sys
from functools import lru_cache
from types import SimpleNamespace

import pytest

ES_LOADER_DIR = os.path.join(
    os.path.dirname(__file__), '..', 'source', 'lambda', 'es_loader')
sys.path.insert(0, os.path.abspath(ES_LOADER_DIR))

import siem  # noqa: E402
from siem import utils  # noqa: E402
from siem.fileformat_json import FileFormatJson  # noqa: E402

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), 'fixtures')


def _load_index_functions(etl_config):
    with open(os.path.join(ES_LOADER_DIR, 'index.py')) as f:
        tree = ast.parse(f.read())
    wanted = ('get_value_from_etl_config', 'create_logconfig')
    funcs = [n for n in tree.body
             if isinstance(n, ast.FunctionDef) and n.name in wanted]
    module = ast.Module(body=funcs, type_ignores=[])
    namespace = {'etl_config': etl_config, 'utils': utils, 're': re,
                 'json': json, 'lru_cache': lru_cache,
                 'logger': SimpleNamespace(exception=print),
                 'SERVICE': 'es', 'log_exclusion_patterns': {},
                 'exclusion_conditions': {}}
    exec(compile(module, 'index.py', 'exec'), namespace)
    return namespace['create_logconfig']


@pytest.fixture(scope='session')
def etl_config():
    return utils.get_etl_config()


@pytest.fixture(scope='session')
def create_logconfig(etl_config):
    return _load_index_functions(etl_config)


@pytest.fixture(scope='session')
def logtype_s3key_dict(etl_config):
    return utils.create_logtype_s3key_dict(etl_config)


class _Disabled:
    is_enabled = False

    def check_ipaddress(self, ipaddr):
        return None, None


def load_fixture(name):
    with open(os.path.join(FIXTURES_DIR, name)) as f:
        return f.read()


@pytest.fixture
def parse_json_log(create_logconfig):
    """parse raw json text as es-loader does and return list of LogParser"""
    def _parse(raw_text, logtype, s3key):
        logconfig = create_logconfig(logtype)
        rawdata = io.TextIOWrapper(
            io.BytesIO(gzip.decompress(gzip.compress(raw_text.encode()))))
        fileformat = FileFormatJson(rawdata, logconfig, logtype)
        logfile = SimpleNamespace(
            logtype=logtype, s3key=s3key, s3bucket='test-bucket',
            file_format='json', accountid='111122223333',
            region='us-east-1', via_firelens=False, error_logs_count=0)
        sf_module = utils.load_sf_module(logfile, logconfig, [])
        results = []
        for lograw, logdict, logmeta in fileformat.extract_log(1, 100):
            parser = siem.LogParser(logfile, logconfig, sf_module,
                                    _Disabled(), _Disabled(), _Disabled())
            parser(lograw, logdict, logmeta)
            results.append(
                {'index': parser.indexname, 'id': parser.doc_id,
                 'doc': json.loads(parser.json)})
        return results
    return _parse
