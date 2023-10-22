# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.10.3-beta.1'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'


import configparser
import datetime
# import gzip
# import io
import ipaddress
import os
import re
import sqlite3
from functools import lru_cache

import boto3
from aws_lambda_powertools import Logger

logger = Logger(child=True)


class DB():
    DB_FILE = 'trusted_proxy.db'
    S3KEY_PREFIX = 'TrustedProxy'
    TMP_DIR = '/tmp'
    DB_FILE_S3KEY = f'{S3KEY_PREFIX}/{DB_FILE}'
    DB_FILE_LOCAL = f'{TMP_DIR}/{DB_FILE}'
    DB_FILE_FRESH_DURATION = 259200   # 3 days
    NOT_FILE_FRESH_DURATION = 43200   # 12 hours
    RE_IPADDR = re.compile(r'[0-9a-fA-F:.]*$')

    def __init__(self, s3_session_config):
        self.GEOIP_BUCKET = self._get_geoip_buckent_name()
        self.s3_session_config = s3_session_config
        has_trusted_proxy_db = self._download_database()
        self.cur = None
        if has_trusted_proxy_db:
            with sqlite3.connect(self.DB_FILE_LOCAL) as conn_file:
                self.conn = sqlite3.connect(':memory:')
                try:
                    conn_file.backup(self.conn)
                    self.cur = self.conn.cursor()
                    self.cur.execute('PRAGMA quick_check')
                    # self.cur.execute('PRAGMA temp_store=2')
                    # self.cur.execute('PRAGMA journal_mode=OFF')
                    # self.cur.execute('PRAGMA synchronous=OFF')
                    # self.cur.execute('PRAGMA locking_mode=EXCLUSIVE')
                    # self.cur.execute('PRAGMA query_only=ON')
                    self.cur.execute('SELECT count(*) FROM ipaddress')
                    count = self.cur.fetchone()[0]
                    if count >= 1:
                        self.is_enabled = True
                    else:
                        self.is_enabled = False
                except Exception:
                    self.conn.close()
                    logger.exception('Invalid Trusted Proxy Database')
                    self.is_enabled = False
        else:
            self.is_enabled = False

    @lru_cache(maxsize=1000000)
    def check_trusted_ipaddress(self, ip_str: str):
        if (self.cur
                and isinstance(ip_str, str)
                and self.RE_IPADDR.match(ip_str)):
            return self._query_db(ip_str)
        else:
            return None

    def select_clientip_from_xff(self, sourceip: str, xff: list):
        clientip = ''
        is_trusted = self.check_trusted_ipaddress(sourceip)
        if not is_trusted:
            # it means that clientip is realip and xff is manipulated
            clientip = sourceip
        else:
            for remoteip in reversed(xff):
                is_trusted = self.check_trusted_ipaddress(remoteip)
                if not is_trusted:
                    # it means that sourceip is proxy and crealip is in xff
                    clientip = remoteip
                    break
        return clientip

    def _get_geoip_buckent_name(self):
        geoipbucket = os.environ.get('GEOIP_BUCKET')
        if not geoipbucket:
            config = configparser.ConfigParser(
                interpolation=configparser.ExtendedInterpolation())
            config.read('aes.ini')
            config.sections()
            if 'aes' in config:
                geoipbucket = config['aes']['GEOIP_BUCKET']
            else:
                logger.warning('Impossible to find GEOIP_BUCKET name in os '
                               'environment')
                geoipbucket = ''
        return geoipbucket

    def _delete_file_older_than_seconds(self, filename, seconds):
        diff = datetime.datetime.now().timestamp() - os.stat(filename).st_ctime
        if diff >= seconds:
            os.remove(filename)
            logger.warning('deleted ' + filename)
            return True
        else:
            logger.warning('kept ' + filename)
            return False

    def _download_database(self) -> bool:
        localfile_not_found = f'{self.TMP_DIR}/not_found_{self.DB_FILE}'
        if os.path.isfile(localfile_not_found):
            del_success = self._delete_file_older_than_seconds(
                localfile_not_found, self.NOT_FILE_FRESH_DURATION)
            if not del_success:
                return False
        elif os.path.isfile(self.DB_FILE_LOCAL):
            del_success = self._delete_file_older_than_seconds(
                self.DB_FILE_LOCAL, self.DB_FILE_FRESH_DURATION)
            if not del_success:
                return True

        if not os.path.isfile(self.DB_FILE_LOCAL):
            _s3 = boto3.resource('s3', config=self.s3_session_config)
            bucket = _s3.Bucket(self.GEOIP_BUCKET)
            try:
                bucket.download_file(self.DB_FILE_S3KEY, self.DB_FILE_LOCAL)
                logger.info(f'downloading {self.DB_FILE} is success')
                return True
            except Exception:
                logger.warning(f'{self.DB_FILE} is not found in s3')
                with open(localfile_not_found, 'w') as f:
                    f.write('')
                return False
            """
            _s3 = boto3.client('s3')
            try:
                s3obj = _s3.get_object(
                    Bucket=self.GEOIP_BUCKET, Key=f'{self.DB_FILE_S3KEY}.gz')
                iofile = gzip.open(io.BytesIO(s3obj['Body'].read()), 'rb')
                with open(self.DB_FILE_LOCAL, 'wb') as f:
                    f.write(iofile.read())
                return True
            except _s3.exceptions.NoSuchKey:
                logger.warning(f'{self.DB_FILE} is not found in s3')
                with open(localfile_not_found, 'w') as f:
                    f.write('')
                return False
            except Exception:
                logger.exception(f'Something bad happened.')
                with open(localfile_not_found, 'w') as f:
                    f.write('')
                return False
            """

    def _del_none(self, d):
        for key, value in list(d.items()):
            if isinstance(value, dict):
                self._del_none(value)
            if isinstance(value, dict) and len(value) == 0:
                del d[key]
            elif isinstance(value, type(None)):
                del d[key]
        return d

    def _query_db(self, ip_str):
        try:
            ip = ipaddress.ip_address(ip_str)
            ip_int = int(ip)
        except Exception:
            return None
        if ip.version == 4:
            self.cur.execute(
                """SELECT provider, name
                FROM (
                    SELECT provider, name, network_end
                    FROM ipaddress
                    WHERE version = 4 AND network_start <= ?
                    ORDER BY network_start DESC
                    LIMIT 20)
                WHERE network_end >= ?""",
                (ip_int, ip_int))
        else:
            ip_int_upper = ip_int >> 80
            ip_int_middle = ip_int >> 32 & (1 << 48) - 1
            ip_int_lower = ip_int & (1 << 32) - 1
            self.cur.execute(
                """SELECT provider, name, network_end
                FROM (
                    SELECT provider, name, network_end,
                        v6_network2_start, v6_network2_end,
                        v6_network1_start, v6_network1_end
                    FROM ipaddress
                    WHERE version = 6 AND network_start <= ?
                    ORDER BY network_start DESC
                    LIMIT 20)
                WHERE network_end >= ?
                    AND v6_network2_start <= ?
                    AND v6_network2_end >= ?
                    AND v6_network1_start <= ?
                    AND v6_network1_end >= ?
                    """,
                (ip_int_lower, ip_int_lower,
                 ip_int_middle, ip_int_middle,
                 ip_int_upper, ip_int_upper))
        res_count = len(self.cur.fetchall())
        if res_count > 0:
            return True
        else:
            return False
