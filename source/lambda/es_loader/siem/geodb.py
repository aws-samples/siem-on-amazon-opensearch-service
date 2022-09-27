# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.8.0c'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import configparser
import datetime
import os
import re
from functools import lru_cache

import boto3
import geoip2.database
from aws_lambda_powertools import Logger

logger = Logger(child=True)


class GeoDB():
    S3KEY_PREFIX = 'GeoLite2/'
    GEOIP_DBS = {'city': 'GeoLite2-City.mmdb', 'asn': 'GeoLite2-ASN.mmdb'}
    DB_FILE_FRESH_DURATION = 864000   # 10 days
    NOT_FILE_FRESH_DURATION = 86400   # 24 hours
    RE_DIGIT = re.compile(r'\d')

    def __init__(self):
        GEOIP_BUCKET = self._get_geoip_buckent_name()
        has_city_db, has_asn_db = False, False
        if GEOIP_BUCKET:
            has_city_db = self._download_geoip_database(
                GEOIP_BUCKET, self.GEOIP_DBS['city'])
            has_asn_db = self._download_geoip_database(
                GEOIP_BUCKET, self.GEOIP_DBS['asn'])
        self._reader_city, self._reader_asn = None, None
        if has_city_db:
            self._reader_city = geoip2.database.Reader(
                '/tmp/' + self.GEOIP_DBS['city'])
        if has_asn_db:
            self._reader_asn = geoip2.database.Reader(
                '/tmp/' + self.GEOIP_DBS['asn'])

    def check_ipaddress(self, ip: str):
        if (ip is None) or (not self.RE_DIGIT.search(ip)):
            return None, None
        return self._get_geo_city(ip), self._get_geo_asn(ip)

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

    def _download_geoip_database(
            self, geoipbucket: str, geodb_name: str) -> bool:
        geoipbucket = geoipbucket
        localfile = '/tmp/' + geodb_name
        localfile_not_found = '/tmp/not_found_' + geodb_name
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
            bucket = s3geo.Bucket(geoipbucket)
            s3obj = self.S3KEY_PREFIX + geodb_name
            try:
                bucket.download_file(s3obj, localfile)
                logger.info(f'downloading {geodb_name} was success')
                return True
            except Exception:
                logger.warning(geodb_name + ' is not found in s3')
                with open(localfile_not_found, 'w') as f:
                    f.write('')
                return False

    @lru_cache(maxsize=1000000)
    def _get_geo_city(self, ip):
        if not self._reader_city:
            return None
        try:
            response = self._reader_city.city(ip)
        except Exception:
            return None
        country_iso_code = response.country.iso_code
        country_name = response.country.name
        city_name = response.city.name
        __lon = response.location.longitude
        __lat = response.location.latitude
        location = {'lon': __lon, 'lat': __lat}
        return {'city_name': city_name, 'country_iso_code': country_iso_code,
                'country_name': country_name, 'location': location}

    @lru_cache(maxsize=1000000)
    def _get_geo_asn(self, ip):
        if not self._reader_asn:
            return None
        try:
            response = self._reader_asn.asn(ip)
        except Exception:
            return None
        return {'number': response.autonomous_system_number,
                'organization': {
                    'name': response.autonomous_system_organization}}
