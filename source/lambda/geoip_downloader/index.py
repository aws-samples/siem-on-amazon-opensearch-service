# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.8.0c'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import hashlib
import json
import os
import tarfile
import urllib.error
import urllib.parse
import urllib.request

import boto3

# get var from lambda environment
s3bucket_name = os.environ['s3bucket_name']
license_key = os.environ.get('license_key', '')
s3key_prefix = os.environ.get('s3key_prefix', 'GeoLite2/')

s3 = boto3.resource('s3')
bucket = s3.Bucket(s3bucket_name)
url = 'https://download.maxmind.com/app/geoip_download?'
put_files = ['GeoLite2-City', 'GeoLite2-ASN', 'GeoLite2-Country']


def download_file(filename):
    for suffix in ['tar.gz', 'tar.gz.sha256']:
        values = {'edition_id': filename, 'license_key': license_key,
                  'suffix': suffix}
        data = urllib.parse.urlencode(values)
        try:
            urllib.request.urlretrieve(
                url + data, filename='/tmp/' + filename + '.' + suffix)
        except urllib.error.HTTPError as err:
            if err.status == 401:
                return err.status
            print(err)
            raise Exception('ERROR: http error')
        except Exception as err:
            print(err)
            raise Exception('ERROR: ' + err)
    print('INFO: ' + filename + ' was downloaded')
    return 200


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
            mmdb, s3bucket_name, s3obj))


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
    if len(license_key) != 16 or license_key == 'x' * 16:
        print('Skip. There is no valid maxmind license')
        status = 401
    else:
        try:
            for filename in put_files:
                status = download_file(filename)
                if status == 401:
                    break
                put_to_s3(filename)
        except Exception as e:
            print(e)

    if status == 200:
        response = {'status': 'geodb files were downloaded'}
    elif status == 401:
        response = {'status': 'invalide license key'}
    else:
        response = {'status': 'unknown error'}
    if event and 'RequestType' in event:
        send(event, context, 'SUCCESS', response, physicalResourceId)
    return response
