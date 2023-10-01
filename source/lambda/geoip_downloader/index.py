# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.10.2-rc.1'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import base64
import hashlib
import ipaddress
import json
import os
import sqlite3
import tarfile
import urllib.error
import urllib.parse
import urllib.request

import boto3

# get var from lambda environment
S3_BUCKET_NAME = os.environ['s3bucket_name']
license_key = os.environ.get('license_key', '')
s3key_prefix = os.environ.get('s3key_prefix', 'GeoLite2/')

s3 = boto3.resource('s3')
bucket = s3.Bucket(S3_BUCKET_NAME)

s3_client = boto3.client('s3')
TRUSTED_PROXY_LIST = os.environ.get('TRUSTED_PROXY_LIST', '')
opener = urllib.request.build_opener()
opener.addheaders = [
    ('User-Agent',
     'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 '
     '(KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36')]


def download_file(url, localfile):
    try:
        urllib.request.install_opener(opener)
        urllib.request.urlretrieve(url, localfile)
    except urllib.error.HTTPError as err:
        if err.status == 401:
            return err.status
        print(f'ERROR: Failure to download file from {url} because {err}')
        return False
    except Exception as err:
        print(f'ERROR: Failure to download file from {url} because {err}')
        return False
    print(f'INFO: {localfile} was downloaded')
    return 200


def download_geodb():
    url_geodb = 'https://download.maxmind.com/app/geoip_download?'
    put_files = ['GeoLite2-City', 'GeoLite2-ASN', 'GeoLite2-Country']
    try:
        for filename in put_files:
            for suffix in ['tar.gz', 'tar.gz.sha256']:
                values = {'edition_id': filename, 'license_key': license_key,
                          'suffix': suffix}
                query = urllib.parse.urlencode(values)
                url = url_geodb + query
                localfile = f'/tmp/{filename}.{suffix}'
                status = download_file(url, localfile)
                if status == 401:
                    break
            put_to_s3(filename)
    except Exception as e:
        print(e)


def initialize_trusted_proxy_db():
    TRUSTED_DB = 'trusted_proxy.db'
    print('INFO: Starting initializing DB')
    con = sqlite3.connect(f'/tmp/{TRUSTED_DB}')
    # confirmd and ignored Rule-884405
    con.execute('PRAGMA journal_mode=MEMORY')
    cur = con.cursor()

    cur.execute("DROP TABLE IF EXISTS ipaddress")
    cur.execute(
        """CREATE TABLE ipaddress(
            provider TEXT,
            name TEXT,
            version INTEGER,
            v6_network1_start INTEGER,
            v6_network1_end INTEGER,
            v6_network2_start INTEGER,
            v6_network2_end INTEGER,
            network_start INTEGER,
            network_end INTEGER,
            UNIQUE(provider, v6_network1_start, v6_network1_end,
                   v6_network2_start, v6_network2_end,
                   network_start, network_end)
        )""")
    con.commit()
    return con, cur


def insert_ipaddr(cur, nw_str, provider=None, name=None):
    if not nw_str:
        return False
    try:
        nw = ipaddress.ip_network(nw_str.strip(), strict=False)
        version = nw.version
    except Exception as err:
        print(f'ERROR: invalid network address, {nw_str} in {provider} '
              f'because {err}')
        return False

    network_start = int(nw[0])
    network_end = int(nw[-1])
    if version == 4:
        v6_network1_start = 0
        v6_network1_end = 0
        v6_network2_start = 0
        v6_network2_end = 0
    elif version == 6:
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
        return False

    try:
        cur.execute(
            """INSERT INTO ipaddress (
                provider, name, version,
                v6_network1_start, v6_network1_end,
                v6_network2_start, v6_network2_end,
                network_start, network_end
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                provider, name, version,
                v6_network1_start, v6_network1_end,
                v6_network2_start, v6_network2_end,
                network_start, network_end))
        return True
    except sqlite3.IntegrityError:
        print(f'DEBUG: duplicated: provider: {provider}, ip: {nw_str}')
    except Exception as e:
        print(e)
        print(
            f'ERROR: unknown error. provider: {provider}, ip: {nw_str}')
    return False


def create_trusted_proxy_db(cur):
    # custom
    try:
        my_proxy_list = ' '.join(TRUSTED_PROXY_LIST.split(',')).split()
        for my_proxy in my_proxy_list:
            my_proxy = my_proxy.strip()
            insert_ipaddr(cur, my_proxy, 'custom', 'custom')
    except Exception as e:
        print('ERROR: invalid trusted proxy list')
        print(f'ERROR: {e}')

    # aws
    url_aws = 'https://ip-ranges.amazonaws.com/ip-ranges.json'
    localfile = '/tmp/ip-ranges.json'
    print('INFO: Started creating DB for AWS')
    download_file(url_aws, localfile)
    if os.path.isfile(localfile):
        with open(localfile) as f:
            cloudfront_dict = json.load(f)
            for item in cloudfront_dict['prefixes']:
                if item.get('service') in ('CLOUDFRONT', 'GLOBALACCELERATOR'):
                    insert_ipaddr(
                        cur, item['ip_prefix'], 'aws', item['service'])
            for item in cloudfront_dict['ipv6_prefixes']:
                if item.get('service') in ('CLOUDFRONT', 'GLOBALACCELERATOR'):
                    insert_ipaddr(
                        cur, item['ipv6_prefix'], 'aws', item['service'])
        os.remove(localfile)

    # cloudflare
    print('INFO: Started creating DB for CloudFlare')
    for filename in ['ips-v4', 'ips-v6']:
        url = f'https://www.cloudflare.com/{filename}'
        localfile = f'/tmp/cloudflare-{filename}'
        download_file(url, localfile)
        if os.path.isfile(localfile):
            with open(localfile) as f:
                for nw_str in f.readlines():
                    insert_ipaddr(cur, nw_str, 'cloudflare', filename)
            os.remove(localfile)

    return cur


def put_db_to_s3(con, cur):
    filename = 'trusted_proxy.db'
    cur.execute("CREATE INDEX idx_nw_start ON ipaddress(network_start)")
    con.commit()

    # check db integrity
    cur.execute("PRAGMA integrity_check")
    res = cur.fetchone()
    if res[0] != 'ok':
        print(f'INFO: {res}')
        raise Exception('failed to create Trusted Proxy database')

    print('INFO: total number of trusted proxy networks')
    cur.execute("SELECT provider,name,version,count(*) "
                "FROM ipaddress GROUP BY provider,name,version")
    for res in cur.fetchall():
        print(f'INFO: {res[0]}, {res[1]}, ipv{res[2]}, {res[3]}')
    con.close()

    # upload
    h = hashlib.md5()
    s3_key = f'TrustedProxy/{filename}'
    with open(f'/tmp/{filename}', 'rb') as f:
        h.update(f.read())
        file_md5 = base64.b64encode(h.digest()).decode('utf-8')
        f.seek(0)
        res = s3_client.put_object(
            Body=f, Bucket=S3_BUCKET_NAME, Key=s3_key, ContentMD5=file_md5,
            ChecksumAlgorithm='sha256')
    status_code = res.get('ResponseMetadata', {}).get('HTTPStatusCode')
    if status_code == 200:
        print('INFO: trusted_proxy_db creation and update was successful')
    return status_code


def put_to_s3(filename):
    with open('/tmp/' + filename + '.tar.gz.sha256') as f:
        checksum = f.read().split()[0]
        print('INFO: Checksum: ' + checksum)

    with open('/tmp/' + filename + '.tar.gz', 'rb') as f:
        calcurated_checksum = hashlib.sha256(f.read()).hexdigest()

    if checksum not in calcurated_checksum:
        print('ERROR: checksum is different. download is failed')
        return False

    with tarfile.open('/tmp/' + filename + '.tar.gz', 'r:gz') as tf:
        directory = tf.getmembers()[0].name
        tf.extractall(path='/tmp/')
        mmdb = directory + '/' + filename + '.mmdb'
        s3obj = s3key_prefix + filename + '.mmdb'
        bucket.upload_file('/tmp/' + mmdb, s3obj)
        print('INFO: uploaded {0} to s3://{1}/{2}'.format(
            mmdb, S3_BUCKET_NAME, s3obj))


def send(event, context, responseStatus, responseData, physicalResourceId=None,
         noEcho=False):
    # https://docs.aws.amazon.com/ja_jp/AWSCloudFormation/latest/UserGuide/cfn-lambda-function-code-cfnresponsemodule.html
    responseUrl = event.get('ResponseURL')
    if responseUrl:
        print(responseUrl)
    else:
        return False

    response_body = {}
    response_body['Status'] = responseStatus
    response_body['Reason'] = ('See the details in CloudWatch Log Stream: '
                               '' + context.log_stream_name)
    response_body['PhysicalResourceId'] = (
        physicalResourceId or context.log_stream_name)
    response_body['StackId'] = event['StackId']
    response_body['RequestId'] = event['RequestId']
    response_body['LogicalResourceId'] = event['LogicalResourceId']
    response_body['NoEcho'] = noEcho
    response_body['Data'] = responseData

    json_response_body = json.dumps(response_body)

    print('Response body:\n' + json_response_body)

    headers = {'content-type': 'application/json', }
    req = urllib.request.Request(
        event['ResponseURL'], json_response_body.encode(),
        headers=headers, method='PUT')
    try:
        res = urllib.request.urlopen(req)
        print('Status code: ' + str(res.status))
    except Exception as e:
        print('send(..) failed executing requests.put(..): ' + str(e))


def lambda_handler(event, context):
    physicalResourceId = 'geoipdb'
    status = 'None'
    if event:
        print(json.dumps(event))
    if len(license_key) not in (16, 40) or license_key == 'x' * 16:
        print('Skip. There is no valid maxmind license')
        status = 401
    else:
        download_geodb()

    if status == 200:
        response = {'status': 'geodb files were downloaded'}
    elif status == 401:
        response = {'status': 'invalide license key'}
    else:
        response = {'status': 'unknown error'}

    try:
        con, cur = initialize_trusted_proxy_db()
        cur = create_trusted_proxy_db(cur)
        put_db_to_s3(con, cur)
    except Exception as e:
        print(f'ERROR: {e}')

    if event and 'RequestType' in event:
        send(event, context, 'SUCCESS', response, physicalResourceId)
    return response


if __name__ == '__main__':
    lambda_handler(None, None)
