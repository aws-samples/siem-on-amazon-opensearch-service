# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.7.2-beta.1'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import configparser
import datetime
import ipaddress
import os
import re
import sqlite3
from functools import lru_cache

import boto3
from aws_lambda_powertools import Logger

logger = Logger(child=True)


class DB():
    S3KEY_PREFIX = 'IOC/'
    IOC_DB = 'ioc.sqlite'
    DB_FILE_FRESH_DURATION = 259200   # 3 days
    NOT_FILE_FRESH_DURATION = 43200   # 12 hours
    RE_IPADDR = re.compile(r'[0-9a-fA-F:.]*$')

    def __init__(self):
        GEOIP_BUCKET = self._get_geoip_buckent_name()
        has_ioc_db = self._download_database(GEOIP_BUCKET, self.IOC_DB)
        self.cur = None
        if has_ioc_db:
            conn_file = sqlite3.connect(f'/tmp/{self.IOC_DB}')
            self.conn = sqlite3.connect(':memory:')
            try:
                conn_file.backup(self.conn)
                conn_file.close()
                self.cur = self.conn.cursor()
                self.cur.execute('PRAGMA quick_check')
                self.cur.execute('SELECT count(*) FROM ipaddress')
                count = self.cur.fetchone()[0]
                if count >= 2:
                    self.is_enabled = True
                else:
                    self.is_enabled = False
            except Exception:
                self.conn.close()
                conn_file.close()
                logger.exception('Invalid IOC Database')
                self.is_enabled = False
        else:
            self.is_enabled = False

    @lru_cache(maxsize=1000000)
    def check_ipaddress(self, ip_str: str):
        if (self.cur
                and isinstance(ip_str, str)
                and self.RE_IPADDR.match(ip_str)):
            return self._enrich_ipaddress(ip_str)
        else:
            return None

    @lru_cache(maxsize=1000000)
    def check_domain(self, domain: str):
        return self._enrich_domain(domain)

    def add_mached_fields(self, enrichments: list, fields: list):
        for x in enrichments:
            x['matched']['field'] = fields
        return enrichments

    def _get_geoip_buckent_name(self):
        if 'GEOIP_BUCKET' in os.environ:
            geoipbucket = os.environ.get('GEOIP_BUCKET', '')
        else:
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

    def _download_database(
            self, s3bucket: str, db_name: str) -> bool:
        localfile = '/tmp/' + db_name
        localfile_not_found = '/tmp/not_found_' + db_name
        if os.path.isfile(localfile_not_found):
            del_success = self._delete_file_older_than_seconds(
                localfile_not_found, self.NOT_FILE_FRESH_DURATION)
            if not del_success:
                return False
        elif os.path.isfile(localfile):
            del_success = self._delete_file_older_than_seconds(
                localfile, self.DB_FILE_FRESH_DURATION)
            if not del_success:
                return True

        if not os.path.isfile(localfile):
            s3geo = boto3.resource('s3')
            bucket = s3geo.Bucket(s3bucket)
            s3obj = self.S3KEY_PREFIX + db_name
            try:
                bucket.download_file(s3obj, localfile)
                logger.info(f'downloading {db_name} was success')
                return True
            except Exception:
                logger.warning(f'{db_name} is not found in s3')
                with open(localfile_not_found, 'w') as f:
                    f.write('')
                return False

    def _del_none(self, d):
        for key, value in list(d.items()):
            if isinstance(value, dict):
                self._del_none(value)
            if isinstance(value, dict) and len(value) == 0:
                del d[key]
            elif isinstance(value, type(None)):
                del d[key]
        return d

    def _enrich_ipaddress(self, ip_str):
        try:
            ip = ipaddress.ip_address(ip_str)
            ip_int = int(ip)
        except Exception:
            return None
        if ip.version == 4:
            self.cur.execute(
                """SELECT provider, type, name, reference, first_seen,
                    last_seen, modified, description
                FROM ipaddress
                WHERE type = 'ipv4-addr'
                    AND network_start <= ?
                    AND network_end >= ?""",
                (ip_int, ip_int))
        else:
            ip_int_upper = ip_int >> 80
            ip_int_middle = ip_int >> 32 & (1 << 48) - 1
            ip_int_lower = ip_int & (1 << 32) - 1
            print(str(ip))
            print(f'{str(ip_int_upper)} - {str(ip_int_middle)} - '
                  f'{str(ip_int_lower)}')
            self.cur.execute(
                """SELECT provider, type, name, reference, first_seen,
                    last_seen, modified, description
                FROM ipaddress
                WHERE type = 'ipv6-addr'
                    AND v6_network1_start <= ?
                    AND v6_network1_end >= ?
                    AND v6_network2_start <= ?
                    AND v6_network2_end >= ?
                    AND network_start <= ?
                    AND network_end >= ?""",
                (ip_int_upper, ip_int_upper, ip_int_middle, ip_int_middle,
                 ip_int_lower, ip_int_lower))
        enrichments = []
        for res in self.cur.fetchall():
            (provider, ioc_type, ioc_name, reference, first_seen,
             last_seen, modified, description) = res
            enrichment = {
                'indicator': {
                    'provider': provider, 'name': ioc_name, 'ip': ip_str,
                    'first_seen': first_seen, 'last_seen': last_seen,
                    'modified_at': modified, 'reference': reference,
                    'type': ioc_type, 'description': description
                },
                'matched': {'field': []}
            }
            enrichment = self._del_none(enrichment)
            enrichments.append(enrichment)
        return enrichments

    def _enrich_domain(self, domain):
        enrichments = []
        self.cur.execute(
            """SELECT provider, type, name, reference, first_seen,
                      last_seen, modified, description
            FROM domain
            WHERE type = ?
                AND domain = ?""",
            ('domain-name', domain))
        for res in self.cur.fetchall():
            (provider, ioc_type, ioc_name, reference, first_seen,
             last_seen, modified, description) = res
            enrichment = {
                'indicator': {
                    'provider': provider, 'name': ioc_name,
                    'first_seen': first_seen, 'last_seen': last_seen,
                    'modified_at': modified, 'reference': reference,
                    'type': ioc_type, 'description': description
                },
                'matched': {
                    'atomic': domain, 'field': []
                }
            }
            enrichment = self._del_none(enrichment)
            enrichments.append(enrichment)
        return enrichments
