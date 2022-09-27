# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.8.0c'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import base64
import datetime
import email.utils
import hashlib
import http.client
import ipaddress
import json
import logging
import os
import sqlite3
import urllib.request
from functools import lru_cache

import boto3
from botocore.config import Config
from botocore.exceptions import ParamValidationError

OBJ_LIMIT = 5000
DB_MAX_SIZE_MB = 128
TMP_DIR = '/tmp'
DB_FILEPATH = f'{TMP_DIR}/ioc.sqlite'
LOCAL_TMP_FILE = f'{TMP_DIR}/ioc.tmp'
S3_BUCKET_NAME = os.environ['GEOIP_BUCKET']
S3_DB_KEY = 'IOC/ioc.sqlite'
LOG_LEVEL = os.getenv('LOG_LEVEL')
IS_TOR = os.getenv('TOR')
IS_ABUSE_CH = os.getenv('ABUSE_CH')
OTX_API_KEY = os.getenv('OTX_API_KEY')


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()
try:
    logger.setLevel(LOG_LEVEL)
except (ValueError, TypeError):
    logger.setLevel('WARNING')

config = Config(connect_timeout=5, retries={'max_attempts': 0})
s3 = boto3.client('s3', config=config)


def _download_file_from_interet(url, file_name=None, http_conn=None,
                                headers={}):
    if http_conn:
        http_conn.request('GET', url, body=None, headers=headers)
    else:
        req = urllib.request.Request(url)
        if len(headers) > 0:
            for header, value in headers.items():
                req.add_header(header, value)
    try:
        if http_conn:
            response = http_conn.getresponse()
            status_code = response.status

        else:
            response = urllib.request.urlopen(req, timeout=61)
            status_code = response.code
    except Exception:
        logger.exception(f'failed to download from {url}')
        return None

    if not file_name:
        file_name = url.split('/')[-1]
    local_file = f'{TMP_DIR}/{file_name}'
    with open(local_file, mode="wb") as f:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            f.write(chunk)

    try:
        modified = email.utils.parsedate_to_datetime(
            response.headers['Last-Modified']).astimezone(
                datetime.timezone.utc).isoformat(
                    timespec='seconds').replace('+00:00', 'Z')
    except Exception:
        modified = None
    res = {'status_code': status_code, 'file_name': file_name,
           'modified': modified}
    return res


def _put_file_to_s3(local_file, s3_key):
    h = hashlib.new('md5')
    file_read_size = h.block_size * (1024 ** 2)
    with open(local_file, 'rb') as f:
        read_bytes = f.read(file_read_size)
        while read_bytes:
            h.update(read_bytes)
            read_bytes = f.read(file_read_size)
        f.seek(0)
        file_md5 = base64.b64encode(h.digest()).decode('utf-8')
        try:
            s3.put_object(Body=f, Bucket=S3_BUCKET_NAME, Key=s3_key,
                          ContentMD5=file_md5, ChecksumAlgorithm='sha1')
        except ParamValidationError:
            s3.put_object(Body=f, Bucket=S3_BUCKET_NAME, Key=s3_key,
                          ContentMD5=file_md5)
        logger.warning(f'File was uploaded to /{s3_key}. MD5: {file_md5}')
        os.remove(local_file)


def _get_file_from_s3(s3_key, local_file=LOCAL_TMP_FILE):
    try:
        s3.download_file(S3_BUCKET_NAME, s3_key, local_file)
        return True
    except Exception:
        return False


def _initialize_db():
    conn = sqlite3.connect(DB_FILEPATH)
    cur = conn.cursor()

    cur.execute("DROP TABLE IF EXISTS ipaddress")
    cur.execute(
        """CREATE TABLE ipaddress(
            provider TEXT,
            type TEXT,
            v6_network1_start INTEGER,
            v6_network1_end INTEGER,
            v6_network2_start INTEGER,
            v6_network2_end INTEGER,
            network_start INTEGER,
            network_end INTEGER,
            name TEXT,
            reference TEXT,
            first_seen TEXT,
            last_seen TEXT,
            modified TEXT,
            description TEXT,
            PRIMARY KEY(provider, v6_network1_start, v6_network1_end,
                        v6_network2_start, v6_network2_end,
                        network_start, network_end)
        )""")
    imds_addr = int(ipaddress.ip_address('169.254.169.254'))
    cur.execute(f"""
        INSERT INTO ipaddress(provider, type,
                              v6_network1_start, v6_network1_end,
                              v6_network2_start, v6_network2_end,
                              network_start, network_end, name)
        VALUES('built-in', 'ipv4-addr', 0, 0, 0, 0,
               {imds_addr}, {imds_addr}, 'IMDS')
    """)
    conn.commit()
    cur.execute("DROP TABLE IF EXISTS domain")
    cur.execute(
        """CREATE TABLE domain(
            provider TEXT,
            type TEXT,
            domain TEXT,
            name TEXT,
            reference TEXT,
            first_seen TEXT,
            last_seen TEXT,
            modified TEXT,
            description TEXT,
            PRIMARY KEY(provider, domain)
        )""")
    conn.commit()
    return conn, cur


@lru_cache(maxsize=1000)
def _convert_str_to_isoformat(dt_str):
    try:
        dt = datetime.datetime.fromisoformat(
            dt_str.replace('Z', '+00:00')).astimezone(datetime.timezone.utc)
        return dt.isoformat(timespec='seconds').replace('+00:00', 'Z')
    except Exception:
        return None


def _insert_ipaddr(
        cur, ioc_type=None, network_start=None, network_end=None, name=None,
        provider=None, reference=None, first_seen=None, last_seen=None,
        modified=None, description=None):
    network_org = network_start
    if ioc_type == 'ipv6-addr':
        # uppper 48bit
        v6_network1_start = network_start >> 80
        v6_network1_end = network_end >> 80
        # next 48bit
        v6_network2_start = (network_start >> 32) & ((1 << 48) - 1)
        v6_network2_end = (network_end >> 32) & ((1 << 48) - 1)
        # lower 32 bit
        network_start = network_start & ((1 << 32) - 1)
        network_end = network_end & ((1 << 32) - 1)
    else:
        v6_network1_start = 0
        v6_network1_end = 0
        v6_network2_start = 0
        v6_network2_end = 0
    try:
        cur.execute(
            """INSERT INTO ipaddress (
                type,
                v6_network1_start,
                v6_network1_end,
                v6_network2_start,
                v6_network2_end,
                network_start,
                network_end,
                name,
                provider,
                reference,
                first_seen,
                last_seen,
                modified,
                description
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (ioc_type, v6_network1_start, v6_network1_end, v6_network2_start,
             v6_network2_end, network_start, network_end, name, provider,
             reference, first_seen, last_seen, modified, description))
        return True
    except sqlite3.IntegrityError:
        logger.debug(f'duplicated: {ipaddress.ip_address(network_org)}')
    except Exception:
        logger.exception(
            f'unknown error. provider: {provider}, '
            f'ip: {ipaddress.ip_address(network_org)}')
    return False


def _insert_domain(
        cur, ioc_type=None, domain=None, name=None,
        provider=None, reference=None, first_seen=None, last_seen=None,
        modified=None, description=None):
    try:
        cur.execute(
            """INSERT INTO domain (
                type,
                domain,
                name,
                provider,
                reference,
                first_seen,
                last_seen,
                modified,
                description
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (ioc_type, domain, name, provider, reference,
             first_seen, last_seen, modified, description))
        return True
    except sqlite3.IntegrityError:
        logger.debug(f'duplicate: {domain}')
        return False


def _put_db_to_s3(conn, cur):
    # check db integrity
    cur.execute("PRAGMA integrity_check")
    res = cur.fetchone()
    if res[0] != 'ok':
        logger.error(f'{res}')
        raise Exception('failed to create IoC database')

    # check ioc number
    ioc_type_dict = {}
    ioc_count = 0
    db_size = 0
    cur.execute("SELECT type,count(*) FROM ipaddress GROUP BY type")
    for res in cur.fetchall():
        ioc_type_dict[res[0]] = res[1]
        ioc_count += res[1]
    cur.execute("SELECT type,count(*) FROM domain GROUP BY type")
    for res in cur.fetchall():
        ioc_type_dict[res[0]] = res[1]
        ioc_count += res[1]
    if ioc_count <= 1:
        logger.error('There is no IoC in IoC database')
        return ioc_type_dict, db_size
    conn.close()

    # check db file size
    db_size = os.path.getsize(DB_FILEPATH)
    if db_size >= (DB_MAX_SIZE_MB * 1024 * 1024):
        raise Exception(
            f'The IoC database is too large at {db_size/1024/1024} MB.'
            f'The file must be {DB_MAX_SIZE_MB} MB or less.')
    _put_file_to_s3(DB_FILEPATH, S3_DB_KEY)
    return ioc_type_dict, db_size


def _list_keys_or_create_dir(prefix, obj_limit=OBJ_LIMIT):
    response = s3.list_objects_v2(
        Bucket=S3_BUCKET_NAME, Prefix=prefix)
    if 'Contents' not in response:
        s3.put_object(Bucket=S3_BUCKET_NAME, Key=prefix)
        return None
    elif (len(response['Contents']) == 1
            and response['Contents'][0].get('Key', '/').endswith('/')):
        return None
    else:
        contents = response['Contents']
        while 'NextContinuationToken' in response:
            token = response['NextContinuationToken']
            response = s3.list_objects_v2(
                Bucket=S3_BUCKET_NAME, Prefix=prefix, ContinuationToken=token)
            contents.extend(response['Contents'])

        contents = [c for c in contents if not c['Key'].endswith('/')]
        logger.warning(
            f'There are {len(contents)} files in /{prefix} directory')
        contents = sorted(
            contents, key=lambda x: x['LastModified'], reverse=True)
        contents = contents[:obj_limit]
        logger.warning(f'Fetching the latest {len(contents)} files from '
                       f'/{prefix} directory')
        return contents


def _stix2_parser(f):
    stix2 = json.load(f)
    if 'objects' not in stix2 or 'id' not in stix2:
        raise Exception('Invalid STIX 2.x format')

    for item in stix2['objects']:
        obj = {}
        obj['name'] = item.get('name')
        obj['description'] = item.get('description')
        obj['modified'] = _convert_str_to_isoformat(item.get('modified'))
        if not obj['modified']:
            obj['modified'] = _convert_str_to_isoformat(item.get('published'))
        obj['last_seen'] = _convert_str_to_isoformat(item.get('last_seen'))
        obj['first_seen'] = _convert_str_to_isoformat(item.get('first_seen'))
        pattern = item.get('pattern')
        if pattern:
            p_value = pattern.split()[-1].rstrip("]").strip("'")
            obj['org_value'] = p_value
            if 'ipv4-addr:' in pattern:
                obj['type'] = 'ipv4-addr'
                ip = ipaddress.ip_network(p_value)
                obj['network_start'] = int(ip[0])
                obj['network_end'] = int(ip[-1])
            elif 'ipv6-addr:' in pattern:
                obj['type'] = 'ipv6-addr'
                ip = ipaddress.ip_network(p_value)
                obj['network_start'] = int(ip[0])
                obj['network_end'] = int(ip[-1])
            elif 'domain-name:value' in pattern:
                obj['type'] = 'domain-name'
                obj['domain'] = p_value
            elif 'url:value' in pattern:
                obj['type'] = 'url'
                obj['url'] = p_value
            elif 'file:hashes.MD5' in pattern:
                obj['type'] = 'hash'
                obj['md5'] = p_value
        yield obj


class TOR:
    TOR_URL = 'https://check.torproject.org/exit-addresses'
    S3_KEY = f'IOC/tmp/TOR/exit-addresses'

    @classmethod
    def plan(self, mapped):
        if IS_TOR and IS_TOR.lower() == 'true':
            mapped.append({'ioc': 'tor'})
        return mapped

    @classmethod
    def download(self):
        res = _download_file_from_interet(self.TOR_URL)
        if not res or res['status_code'] != 200:
            # use existing downloaded file
            return {'ioc': 'tor'}
        file_name = res['file_name']
        local_file = f'{TMP_DIR}/{file_name}'
        _put_file_to_s3(local_file, self.S3_KEY)
        return {'ioc': 'tor'}

    @classmethod
    def createdb(self, conn, cur):
        name = 'TOR'
        provider = 'torproject.org'
        ioc_type = 'ipv4-addr'

        org_ioc = 0
        inserted_count = 0
        _get_file_from_s3(self.S3_KEY, LOCAL_TMP_FILE)
        if not os.path.exists(LOCAL_TMP_FILE):
            logger.error('There is no downloaed TOR file')
            return cur, inserted_count
        with open(LOCAL_TMP_FILE) as f:
            # ExitNode 5C3F3217F99D6CFA711D9415AFED1003971201AF
            # Published 2022-06-18 20:05:14
            # LastStatus 2022-06-19 05:00:00
            # ExitAddress 185.112.146.73 2022-06-19 05:08:45
            for line in f.readlines():
                if line.split()[0] == 'ExitNode':
                    exit_node = line.split()[1]
                    continue
                elif line.split()[0] == 'Published':
                    continue
                elif line.split()[0] == 'LastStatus':
                    # last_seen = datetime.datetime.fromisoformat(
                    #    f"{line.split()[1]}T{line.split()[2]}").timestamp()
                    last_seen = f"{line.split()[1]}T{line.split()[2]}Z"
                    continue
                elif line.split()[0] == 'ExitAddress':
                    ip_str = line.split()[1]
                    # modified = datetime.datetime.fromisoformat(
                    #    f"{line.split()[2]}T{line.split()[3]}").timestamp()
                    modified = f"{line.split()[2]}T{line.split()[3]}Z"
                org_ioc += 1
                try:
                    ip = ipaddress.ip_address(ip_str)
                except Exception:
                    logger.error(f'invliad ip address format: {repr(ip_str)}')
                    continue
                reference = ("https://metrics.torproject.org/rs.html#details"
                             f"/{exit_node}")
                res = _insert_ipaddr(
                    cur, ioc_type=ioc_type, network_start=int(ip),
                    network_end=int(ip), name=name, provider=provider,
                    reference=reference, last_seen=last_seen,
                    modified=modified)
                if res:
                    inserted_count += 1
        os.remove(LOCAL_TMP_FILE)
        logger.warning(f'{provider}: Original IOC is {org_ioc}')
        logger.warning(f'{provider}: Inserted IOC is {inserted_count}')
        conn.commit()
        return cur, inserted_count


class AbuseCh:
    ABUSE_CH_URL = 'https://feodotracker.abuse.ch/downloads/ipblocklist.json'
    S3_KEY = f'IOC/tmp/ABUSE_CH/ipblocklist.json'

    @classmethod
    def plan(self, mapped):
        if IS_ABUSE_CH and IS_ABUSE_CH.lower() == 'true':
            mapped.append({'ioc': 'abuse_ch'})
        return mapped

    @classmethod
    def download(self):
        res = _download_file_from_interet(self.ABUSE_CH_URL)
        if not res or res['status_code'] != 200:
            # use existing downloaded file
            return {'ioc': 'abuse_ch'}
        file_name = res['file_name']
        local_file = f'{TMP_DIR}/{file_name}'
        _put_file_to_s3(local_file, self.S3_KEY)
        return {'ioc': 'abuse_ch', 'modified': res['modified']}

    @classmethod
    def createdb(self, conn, cur, modified=None):
        provider = 'abuse.ch'
        ioc_type = 'ipv4-addr'

        org_ioc = 0
        inserted_count = 0
        _get_file_from_s3(self.S3_KEY, LOCAL_TMP_FILE)
        if not os.path.exists(LOCAL_TMP_FILE):
            logger.error('There is no downloaed abuse.ch file')
            return cur, inserted_count
        with open(LOCAL_TMP_FILE) as f:
            objs = json.load(f)
        for obj in objs:
            org_ioc += 1
            ip_str = obj['ip_address']
            ip = int(ipaddress.ip_address(ip_str))
            name = obj['malware']
            reference = f'https://feodotracker.abuse.ch/browse/host/{ip_str}/'
            first_seen = obj['first_seen'].replace(' ', 'T') + 'Z'
            # first_seen = datetime.datetime.fromisoformat(
            #    f"{first_seen.split()[0]}T{first_seen.split()[1]}").timestamp()
            last_seen = obj['last_online'] + 'T00:00:00Z'
            # last_seen = datetime.datetime.fromisoformat(
            #    f'{last_seen}T00:00:00').timestamp()
            description = f"status is {obj['status']}"
            res = _insert_ipaddr(
                cur, ioc_type=ioc_type, network_start=int(ip),
                network_end=int(ip), name=name, provider=provider,
                reference=reference, first_seen=first_seen,
                last_seen=last_seen, modified=modified,
                description=description)
            if res:
                inserted_count += 1

        os.remove(LOCAL_TMP_FILE)
        logger.warning(f'{provider}: Original IOC is {org_ioc}')
        logger.warning(f'{provider}: Inserted IOC is {inserted_count}')
        conn.commit()
        return cur, inserted_count


class OTX:
    PREFIX_S3_KEY = 'IOC/tmp/OTX/'
    SLICE = 300
    URL = 'https://otx.alienvault.com/'

    @classmethod
    def plan(self, mapped):
        if (OTX_API_KEY
                and len(OTX_API_KEY) == 64
                and 'xxxxxxxxxx' not in OTX_API_KEY):
            api = 'api/v1/pulses/subscribed_pulse_ids'
            url = f'{self.URL}{api}'
            file_name = 'subscribed_pulse_ids'
            local_file = f'{TMP_DIR}/{file_name}'
            headers = {'X-OTX-API-KEY': OTX_API_KEY}
            res = _download_file_from_interet(
                url, file_name=file_name, headers=headers)
            if not res:
                return mapped
            with open(local_file, 'rt') as f:
                subscribed_pulse = json.load(f)
            logger.warning(
                f'Number of subscribed pulse is {subscribed_pulse["count"]}')
            logger.info(f'next is {subscribed_pulse["next"]}')
            all_ids = subscribed_pulse['results']

            while subscribed_pulse["next"]:
                url = subscribed_pulse["next"]
                res = _download_file_from_interet(
                    url, file_name=file_name, headers=headers)
                with open(local_file, 'rt') as f:
                    subscribed_pulse = json.load(f)
                all_ids.extend(subscribed_pulse['results'])

            all_ids = sorted(all_ids, reverse=True)[:OBJ_LIMIT]
            logger.warning(f'Number of downloading files is {len(all_ids)}')

            n = self.SLICE
            for i in range(0, len(all_ids), n):
                mapped.append({'ioc': 'otx', 'ids': all_ids[i: i + n]})
            if os.path.exists(local_file):
                os.remove(local_file)

        return mapped

    @classmethod
    def download(self, ids):
        o = urllib.parse.urlparse(self.URL)
        if o.scheme == 'https':
            conn = http.client.HTTPSConnection(o.hostname, o.port, timeout=900)
        headers = {'X-OTX-API-KEY': OTX_API_KEY}
        api = 'api/v1/pulses/'
        for id in ids:
            url = f'{self.URL}{api}{id}'
            res = _download_file_from_interet(
                url, file_name=id, headers=headers, http_conn=conn)
            if res and res['status_code'] == 200:
                local_file = f'{TMP_DIR}/{id}'
                s3_key = f'{self.PREFIX_S3_KEY}{id}.json'
                _put_file_to_s3(local_file, s3_key)
        return {'ioc': 'otx'}

    @classmethod
    def createdb(self, conn, cur):
        s3_objs = _list_keys_or_create_dir(
            self.PREFIX_S3_KEY, obj_limit=(OBJ_LIMIT * 2))
        provider = 'AlienVault_OTX'
        file_count = 0
        all_org_ioc = 0
        all_inserted_count = 0
        for s3_obj in s3_objs:
            file_count += 1
            org_ioc = 0
            inserted_count = 0
            s3_key = s3_obj['Key']
            res = _get_file_from_s3(s3_key, LOCAL_TMP_FILE)
            if not res:
                continue
            with open(LOCAL_TMP_FILE) as f:
                try:
                    otx_obj = json.load(f)
                except Exception:
                    logger.exception(f'{s3_key}: Invalid OTX format file')
                    continue
            name = otx_obj.get('name')
            _description = otx_obj.get('description')
            modified = _convert_str_to_isoformat(otx_obj.get('modified'))
            for item in otx_obj['indicators']:
                ioc_type = item.get('type')
                if ioc_type not in ('IPv4', 'IPv6', 'domain', 'hostname'):
                    continue
                org_ioc += 1
                description = _description
                if item.get('title'):
                    description = f"{description}. {item.get('title')}"
                if item.get('description'):
                    description = (
                        f"{description}. {item.get('description')}")

                if ioc_type in ('IPv4', 'IPv6'):
                    if ioc_type == 'IPv6':
                        ioc_type = 'ipv6-addr'
                    else:
                        ioc_type = 'ipv4-addr'
                    try:
                        ip = ipaddress.ip_network(item['indicator'])
                    except Exception:
                        continue
                    start, end = int(ip[0]), int(ip[-1])
                    reference = ('https://otx.alienvault.com/indicator/ip/'
                                 f'{item["indicator"]}')
                    res = _insert_ipaddr(
                        cur, ioc_type=ioc_type, network_start=start,
                        network_end=end, name=name, provider=provider,
                        reference=reference, modified=modified,
                        description=description)
                    if res:
                        inserted_count += 1
                elif ioc_type in ('domain', 'hostname'):
                    domain = item['indicator']
                    reference = (f'https://otx.alienvault.com/indicator/'
                                 f'{ioc_type}/{domain}')
                    res = _insert_domain(
                        cur, ioc_type='domain-name', domain=domain, name=name,
                        provider=provider, reference=reference,
                        modified=modified, description=description)
                    if res:
                        inserted_count += 1
            if os.path.exists(LOCAL_TMP_FILE):
                os.remove(LOCAL_TMP_FILE)
            logger.info(f'{provider} {s3_key}: Original IOC is {org_ioc}')
            logger.info(
                f'{provider} {s3_key}: Inserted IOC is {inserted_count}')
            conn.commit()
            all_org_ioc += org_ioc
            all_inserted_count += inserted_count
        logger.warning(f'{provider}: Number of files is {file_count}')
        logger.warning(f'{provider}: Original IOC is {all_org_ioc}')
        logger.warning(f'{provider}: Inserted IOC is {all_inserted_count}')
        return cur, all_inserted_count


def plan(event, context):
    logger.warning('Starting to plan map')
    mapped = []
    mapped = TOR.plan(mapped)
    mapped = AbuseCh.plan(mapped)
    mapped = OTX.plan(mapped)
    summary = {}
    for obj in mapped:
        ioc = obj['ioc']
        if ioc in summary:
            summary[ioc] += 1
        else:
            summary[ioc] = 1
    logger.warning('Mapped sammary: ' + json.dumps(summary))
    return {'summary': summary, 'mapped': mapped}


def download(event, context):
    logger.info(f'Starting download: {event}')
    mapped = event['mapped']
    result = {}
    if mapped['ioc'] == 'tor':
        result = TOR.download()
    elif mapped['ioc'] == 'abuse_ch':
        result = AbuseCh.download()
    elif mapped['ioc'] == 'otx':
        result = OTX.download(mapped['ids'])
    return result


def createdb(event, context):
    logger.warning('Starting to create database')
    if os.path.exists(DB_FILEPATH):
        os.remove(DB_FILEPATH)
    is_tor, is_abuse_ch, is_otx = None, None, None
    provider = {'built-in': 1}
    for item in event:
        try:
            is_provider = item['ioc']
        except Exception:
            continue
        if is_provider:
            if is_provider == 'tor':
                is_tor = True
            elif is_provider == 'abuse_ch':
                is_abuse_ch = True
                abuse_ch_modified = item['modified']
            elif is_provider == 'otx':
                is_otx = True
    conn, cur = _initialize_db()
    cur, provider['custom TXT'] = createdb_custom_txt(conn, cur)
    cur, provider['custom STIX2'] = createdb_custom_stix2(conn, cur)
    if is_tor:
        cur, count = TOR.createdb(conn, cur)
        provider['TOR'] = count
    if is_abuse_ch:
        cur, count = AbuseCh.createdb(conn, cur, abuse_ch_modified)
        provider['MalwareBazaar - Abuse.ch'] = count
    if is_otx:
        cur, count = OTX.createdb(conn, cur)
        provider['AlienVault OTX'] = count
    ioc_type_dict, ioc_db_size = _put_db_to_s3(conn, cur)
    result = {'status': 200, 'ioc_provider': provider,
              'ioc_type': ioc_type_dict,
              'ioc_db_size': f'{ioc_db_size/1024/1024} MB'}
    logger.warning(result)
    return result


def createdb_custom_stix2(conn, cur):
    prefix = 'IOC/STIX2/'
    contents = _list_keys_or_create_dir(prefix)
    all_inserted_count = 0
    if not contents:
        return cur, all_inserted_count
    for content in contents:
        org_ioc = 0
        inserted_count = 0
        s3_key = content['Key']
        provider = s3_key.split('/')[2]
        if provider == s3_key.split('/')[-1]:
            provider = 'custom'
        _name = s3_key.split('/')[-1]

        _get_file_from_s3(s3_key, LOCAL_TMP_FILE)
        with open(LOCAL_TMP_FILE, 'rt') as f:
            try:
                _stix2_parser(f).__next__()
            except Exception:
                logger.exception(f'{s3_key}: Invalid STIX 2.x format file')
                continue
            f.seek(0)
            for item in _stix2_parser(f):
                ioc_type = item.get('type')
                if ioc_type not in ('ipv4-addr', 'ipv6-addr', 'domain-name'):
                    continue
                if item.get('name'):
                    name = f"{_name}: {item['name']}"
                else:
                    name = _name
                org_ioc += 1
                if ioc_type in ('ipv4-addr', 'ipv6-addr'):
                    res = _insert_ipaddr(
                        cur, ioc_type=ioc_type,
                        network_start=item['network_start'],
                        network_end=item['network_end'],
                        name=name, provider=provider,
                        reference=None,
                        first_seen=item['first_seen'],
                        last_seen=item['last_seen'],
                        modified=item['modified'],
                        description=item['description'])
                    if res:
                        inserted_count += 1
                elif ioc_type == 'domain-name':
                    res = _insert_domain(
                        cur, ioc_type=ioc_type,
                        domain=item['domain'],
                        name=name, provider=provider,
                        reference=None,
                        first_seen=item['first_seen'],
                        last_seen=item['last_seen'],
                        modified=item['modified'],
                        description=item['description'])
                    if res:
                        inserted_count += 1
        logger.warning(f'{s3_key}: Original IOC is {org_ioc}')
        logger.warning(f'{s3_key}: Inserted IOC is {inserted_count}')
        conn.commit()
        all_inserted_count += inserted_count
    return cur, all_inserted_count


def createdb_custom_txt(conn, cur):
    prefix = 'IOC/TXT/'
    contents = _list_keys_or_create_dir(prefix)
    all_inserted_count = 0
    if not contents:
        return cur, all_inserted_count
    for content in contents:
        s3_key = content['Key']
        provider = s3_key.split('/')[2]
        if provider == s3_key.split('/')[-1]:
            provider = 'custom'
        name = s3_key.split('/')[-1]

        # list txt files
        _get_file_from_s3(s3_key, LOCAL_TMP_FILE)
        with open(LOCAL_TMP_FILE, 'rt') as f:
            ip_list = []
            try:
                lines = f.readlines()
            except Exception:
                logger.exception(f'{s3_key}: Invalid text file')
                continue
            for line in lines:
                ip_str = line.strip()
                try:
                    ip = ipaddress.ip_network(ip_str)
                except Exception:
                    logger.info(f'invalid ip address format: {repr(line)}')
                    continue
                ip_list.append(ip)
        os.remove(LOCAL_TMP_FILE)

        ip_list.sort(key=lambda x: (isinstance(x, ipaddress.IPv6Network), x))

        # insert ioc into database
        network_start = 0
        network_end = 0
        network_temp = 0
        inserted_count = 0
        modified = content['LastModified'].astimezone(
            datetime.timezone.utc).isoformat(
                timespec='seconds').replace('+00:00', 'Z')
        for ip in ip_list:
            if int(network_end) == 0:
                network_start = int(ip[0])
                network_end = int(ip[-1])
                network_temp = int(ip[-1])
                ioc_type = 'ipv4-addr'
                if isinstance(ip, ipaddress.IPv6Network):
                    ioc_type = 'ipv6-addr'
            elif int(network_temp) + 1 == int(ip[0]):
                network_end = int(ip[-1])
                network_temp = int(ip[-1])
                ioc_type = 'ipv4-addr'
                if isinstance(ip, ipaddress.IPv6Network):
                    ioc_type = 'ipv6-addr'
            else:
                _insert_ipaddr(
                    cur, provider=provider, ioc_type=ioc_type,
                    network_start=network_start, network_end=network_end,
                    name=name, modified=modified)
                inserted_count += 1
                network_start = int(ip[0])
                network_end = int(ip[-1])
                network_temp = int(ip[-1])
        if network_end != 0 and network_temp == network_end:
            ioc_type = 'ipv4-addr'
            if isinstance(ip, ipaddress.IPv6Network):
                ioc_type = 'ipv6-addr'
            _insert_ipaddr(
                cur, provider=provider, ioc_type=ioc_type,
                network_start=network_start, network_end=network_end,
                name=name, modified=modified)
            inserted_count += 1

        logger.warning(f'{s3_key}: Original IOC is {len(ip_list)}')
        logger.warning(f'{s3_key}: Inserted IOC is {inserted_count}')
        conn.commit()
        all_inserted_count += inserted_count
    return cur, all_inserted_count


if __name__ == '__main__':
    event_downloaded = []
    event_planned = plan(None, None)
    for raw_event in event_planned['mapped']:
        event = {'mapped': raw_event}
        result = download(event, None)
        event_downloaded.append(result)
    createdb(event_downloaded, None)
