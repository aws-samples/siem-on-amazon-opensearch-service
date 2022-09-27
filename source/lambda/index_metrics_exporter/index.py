#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.8.0c'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import collections
import datetime
import gzip
import json
import os
import uuid

import boto3
import requests
from opensearchpy import AWSV4SignerAuth, OpenSearch, RequestsHttpConnection

TIMEOUT = 10.0

ES_ENDPOINT = os.getenv('ES_ENDPOINT')
REGION = ES_ENDPOINT.split('.')[1]
BUCKET_NAME = os.getenv('LOG_BUCKET')
PERIOD_HOUR = int(os.getenv('PERIOD_HOUR', 1))

credentials = boto3.Session().get_credentials()
awsauth = AWSV4SignerAuth(credentials, REGION)

client = OpenSearch(
    hosts=[{'host': ES_ENDPOINT, 'port': 443}], http_auth=awsauth,
    use_ssl=True, verify_certs=True, connection_class=RequestsHttpConnection
)

s3_resource = boto3.resource('s3')
bucket = s3_resource.Bucket(BUCKET_NAME)


def set_index_metrics_schema(d):
    metrics_type = 'index'
    INDEX_METRICS_SCHEMA = {
        "@timestamp": TIMESTAMP,
        "opensearch": {
            "cluster": {
                "id": CLUSTER_ID,
                "name": CLUSTER_NAME
            },
            "index": {
                "name": d['index_name'],
                "primaries": {
                    "docs": {
                        "count": None,
                        "deleted": None
                    },
                    "indexing": {
                        "index_time_in_millis": None,
                        "index_total": None,
                        "throttle_time_in_millis": None
                    },
                    "merges": {
                        "total_size_in_bytes": None
                    },
                    "refresh": {
                        "total_time_in_millis": None
                    },
                    "segments": {
                        "count": None
                    },
                    "store": {
                        "size_in_bytes": None
                    }
                },
                "shards": {
                    "total": d['shard_total'],
                    "primaries": d['shard_primaries'],
                },
                "index_status": d['index_status'],
                "status": d['index_health'],
                "total": {
                    "docs": {
                        "count": None,
                        "deleted": None
                    },
                    "fielddata": {
                        "memory_size_in_bytes": None
                    },
                    "indexing": {
                        "index_time_in_millis": None,
                        "index_total": None,
                        "throttle_time_in_millis": None
                    },
                    "merges": {
                        "total_size_in_bytes": None
                    },
                    "refresh": {
                        "total_time_in_millis": None
                    },
                    "search": {
                        "query_time_in_millis": None,
                        "query_total": None
                    },
                    "segments": {
                        "count": None,
                        "doc_values_memory_in_bytes": None,
                        "fixed_bit_set_memory_in_bytes": None,
                        "index_writer_memory_in_bytes": None,
                        "memory_in_bytes": None,
                        "norms_memory_in_bytes": None,
                        "points_memory_in_bytes": None,
                        "stored_fields_memory_in_bytes": None,
                        "term_vectors_memory_in_bytes": None,
                        "terms_memory_in_bytes": None,
                        "version_map_memory_in_bytes": None
                    },
                    "store": {
                        "size_in_bytes": d['total_store_size_in_bytes']
                    }
                },
                "creation": {
                    "date": d['creation_date']
                },
                "storage_tier": d['storage_tier'],
                "start_time": d['start_time'],
                "end_time": d['end_time'],
                "uuid": d['uuid']
            }
        },
        "event": {
            "dataset": f"opensearch.{metrics_type}"
        },
        "metricset": {
            "name": metrics_type,
            "period": PERIOD_HOUR * 60 * 60 * 1000
        }
    }
    return INDEX_METRICS_SCHEMA


def set_shard_metrics_schema(d):
    metrics_type = 'shard'
    SHARD_METRICS_SCHEMA = {
        "@timestamp": TIMESTAMP,
        "opensearch": {
            "cluster": {
                "id": CLUSTER_ID,
                "name": CLUSTER_NAME
            },
            "index": {
                "index_status": d['index_status'],
                "name": d['index_name'],
                "status": d['health'],
                "storage_tier": d['storage_tier']
            },
            "node": {
                "id": d['node_id']
            },
            "shard": {
                "docs": {
                    "count": d['docs_count']
                },
                "number": d['shard_number'],
                "primary": d['shard_primary'],
                "source_node": {
                    "name": d['node'],
                    "uuid": d['id']
                },
                "store": {
                    "size_in_bytes": d['store']
                },
                "state": d['state']
            }
        },
        "event": {
            "dataset": f"opensearch.{metrics_type}"
        },
        "metricset": {
            "name": metrics_type,
            "period": PERIOD_HOUR * 60 * 60 * 1000
        }
    }
    return SHARD_METRICS_SCHEMA


def del_none(d):
    for key, value in list(d.items()):
        if isinstance(value, dict):
            del_none(value)
        if isinstance(value, dict) and len(value) == 0:
            del d[key]
        elif isinstance(value, type(None)):
            del d[key]
    return d


def get_cluster_id_name():
    url = f'https://{ES_ENDPOINT}/'
    try:
        res = requests.get(url=url, auth=awsauth, timeout=TIMEOUT)
    except requests.exceptions.Timeout:
        print(f'ERROR: timeout, skip {url}')
        return None, None
    except Exception as err:
        print(f'ERROR: unknown error, skip {url}')
        print(f'ERROR: {err}')
        return None, None
    cluster_id = res.json()['cluster_uuid']
    cluster_name = res.json()['cluster_name'].split(':')[1]
    return cluster_id, cluster_name


##############################################################################
# INDEX
##############################################################################
def adjust_metrics_by_schema(schema, metrics, path=None):
    if path is None:
        path = []
    for key in schema:
        if key in metrics:
            if isinstance(schema[key], dict) \
                    and isinstance(metrics[key], dict):
                adjust_metrics_by_schema(
                    schema[key], metrics[key], path + [str(key)])
            elif metrics[key]:
                schema[key] = metrics[key]
    return schema


def transform_index_metrics(index, res_json, index_status_dict):
    if index not in index_status_dict:
        return None
    tier = index_status_dict[index]['tier']
    index_status = index_status_dict[index]['status']

    d = collections.defaultdict(lambda: None)
    d['index_name'] = index
    d['index_health'] = index_status_dict[index]['health']
    d['index_status'] = index_status
    d['storage_tier'] = tier
    d['creation_date'] = index_status_dict[index]['creation.date.string']
    if tier == 'cold':
        d['uuid'] = index_status_dict[index]['index_cold_uuid']
        d['total_store_size_in_bytes'] = index_status_dict[index]['size']
        d['start_time'] = index_status_dict[index].get('start_time')
        d['end_time'] = index_status_dict[index].get('end_time')
    if 'pri' in index_status_dict[index]:
        d['shard_primaries'] = int(index_status_dict[index]['pri'])
        d['shard_total'] = d['shard_primaries'] * (
            int(index_status_dict[index]['rep']) + 1)

    metrics = set_index_metrics_schema(d)
    if res_json:
        metrics['opensearch']['index'] = adjust_metrics_by_schema(
            metrics['opensearch']['index'], res_json)

    if tier == 'warm':
        metrics['opensearch']['index']['total']['docs'] = (
            metrics['opensearch']['index']['primaries']['docs'])
        metrics['opensearch']['index']['total']['store'] = (
            metrics['opensearch']['index']['primaries']['store'])

    del d
    return del_none(metrics)


def get_hotwarm_index_status_dict(tier, index_status_dict={}):
    print(f'INFO: Start get_hotwarm_index_status_dict, {tier}')
    url = f'https://{ES_ENDPOINT}/_cat/indices/_{tier}'
    params = {'v': 'true', 's': 'index', 'format': 'json',
              'expand_wildcards': 'all',
              'h': ('health,status,index,creation.date.string,pri,rep')}
    try:
        res = requests.get(
            url=url, params=params, auth=awsauth, timeout=TIMEOUT)
    except requests.exceptions.Timeout:
        print(f'ERROR: timeout, skip {url}')
        return False
    except Exception as err:
        print(f'ERROR: unknown error, skip {url}')
        print(f'ERROR: {err}')
        return False
    if res.status_code != 200:
        print(f'ERROR: {url}')
        print(f'ERROR: {res.json()}')
        return False

    for index_dict in res.json():
        index_name = index_dict.pop('index')
        index_status_dict[index_name] = index_dict
        index_status_dict[index_name]['tier'] = tier

    print(f'INFO: Done  get_hotwarm_index_status_dict, {tier}')
    return index_status_dict


def get_cold_index_status_dict(index_status_dict):
    print(f'INFO: Start get_cold_index_status_dict')
    url = f'https://{ES_ENDPOINT}/_cold/indices/_search'
    headers = {'Content-Type': 'application/json'}
    try:
        res = requests.get(
            url, params={'page_size': 2000}, auth=awsauth, timeout=TIMEOUT)
    except requests.exceptions.Timeout:
        print(f'ERROR: timeout, skip {url}')
        return False
    except Exception as err:
        print(f'ERROR: unknown error, skip {url}')
        print(f'ERROR: {err}')
        return False
    while res.status_code == 200 and len(res.json()['indices']) > 0:
        for index_dict in res.json()['indices']:
            index = index_dict.pop('index')
            index_status_dict[index] = index_dict
            index_status_dict[index]['tier'] = 'cold'
            index_status_dict[index]['status'] = 'cold'
            index_status_dict[index]['health'] = 'green'
            index_status_dict[index]['creation.date.string'] = index_dict.pop(
                'creation_date')
        pagination_id = res.json()['pagination_id']
        body = f'{{"pagination_id": "{pagination_id}"}}'
        try:
            res = requests.post(
                url, data=body, auth=awsauth, headers=headers, timeout=TIMEOUT)
        except requests.exceptions.Timeout:
            print(f'ERROR: timeout, skip {url}')
            return False
    print(f'INFO: Done  get_cold_index_status_dict')
    return index_status_dict


def get_write_hotwarm_index_metrics(fp, index_status_dict):
    print(f'INFO: Start get_write_hotwarm_index_metrics')
    url = (f'https://{ES_ENDPOINT}/_stats/docs,indexing,merge,refresh,'
           'segments,store,fielddata,search')
    headers = {'Content-Type': 'application/json'}
    try:
        res = requests.get(
            url=url, headers=headers, auth=awsauth, timeout=TIMEOUT)
    except requests.exceptions.Timeout:
        print(f'ERROR: timeout, skip {url}')
        return False
    except requests.exceptions.Timeout:
        print(f'ERROR: timeout, skip {url}')
        return False
    except Exception as err:
        print(f'ERROR: unknown error, skip {url}')
        print(f'ERROR: {err}')
        return False
    if res.status_code != 200:
        print(f'ERROR: {url}')
        print(f'ERROR: {res.json()}')
        return False

    indices = res.json()['indices']
    for index, value in indices.items():
        index_metrics = transform_index_metrics(
            index, value, index_status_dict)
        if index_metrics:
            fp.write(json.dumps(index_metrics) + '\n')
    print(f'INFO: Done  get_write_hotwarm_index_metrics')


def get_write_coldclose_index_metrics(fp, index_status_dict):
    print(f'INFO: Start get_write_coldclose_index_metrics')
    for index, index_status in index_status_dict.items():
        if index_status.get('status') in ('cold', 'close'):
            index_metrics = transform_index_metrics(
                index, None, index_status_dict)
            if index_metrics:
                fp.write(json.dumps(index_metrics) + '\n')
    print(f'INFO: Done  get_write_coldclose_index_metrics')


##############################################################################
# SHARD
##############################################################################
def get_shard_metrics():
    print(f'INFO: Start get_shard_metrics')
    # GET _search_shards
    # GET _cat/shards?help
    url = f'https://{ES_ENDPOINT}/_cat/shards'
    params = {'v': 'true', 's': 'index', 'bytes': 'b', 'format': 'json',
              'h': ('index,shard,prirep,state,docs,store,id,node')}
    try:
        res = requests.get(
            url=url, params=params, auth=awsauth, timeout=TIMEOUT)
    except requests.exceptions.Timeout:
        print(f'ERROR: timeout, skip {url}')
        return False
    except Exception as err:
        print(f'ERROR: unknown error, skip {url}')
        print(f'ERROR: {err}')
        return False
    if res.status_code != 200:
        print(f'ERROR: {url}')
        print(f'ERROR: {res.json()}')
        return False
    print(f'INFO: Done  get_shard_metrics')
    return res.json()


def get_write_shard_metrics(fp, index_status_dict):
    print(f'INFO: Start get_write_shard_metrics')
    shard_metrics_list = get_shard_metrics()
    for raw_shard_metrics in shard_metrics_list:
        if not raw_shard_metrics:
            continue
        d = collections.defaultdict(lambda: None)
        primary = True if raw_shard_metrics['prirep'] == 'p' else False
        index_name = raw_shard_metrics.get('index')
        index_status = index_status_dict.get(index_name, {})

        d['index_name'] = index_name
        d['index_status'] = index_status.get('status')
        d['health'] = index_status.get('health')
        d['storage_tier'] = index_status.get('tier')
        d['node_id'] = raw_shard_metrics['id']
        d['docs_count'] = raw_shard_metrics.get('docs')
        d['shard_number'] = raw_shard_metrics['shard']
        d['shard_primary'] = primary
        d['node'] = raw_shard_metrics['node']
        d['id'] = raw_shard_metrics['id']
        d['store'] = raw_shard_metrics.get('store')
        d['state'] = raw_shard_metrics.get('state')

        shard_metrics = set_shard_metrics_schema(d)

        fp.write(json.dumps(del_none(shard_metrics)) + '\n')
        del d
    print(f'INFO: Done  get_write_shard_metrics')


##############################################################################
# Main
##############################################################################
TIMESTAMP = datetime.datetime.utcnow().isoformat() + 'Z'
CLUSTER_ID, CLUSTER_NAME = get_cluster_id_name()


def lambda_handler(event, context):
    try:
        AWS_ID = str(context.invoked_function_arn.split(':')[4])
    except Exception:
        AWS_ID = str(boto3.client("sts").get_caller_identity()["Account"])
    file_name = f'aos_index_metrics_{uuid.uuid4().hex}.json.gz'
    index_status_dict = get_hotwarm_index_status_dict('hot')
    index_status_dict = get_hotwarm_index_status_dict(
        'warm', index_status_dict)
    index_status_dict = get_cold_index_status_dict(index_status_dict)

    with gzip.open(f'/tmp/{file_name}', 'wt') as fp:
        get_write_hotwarm_index_metrics(fp, index_status_dict)
        get_write_coldclose_index_metrics(fp, index_status_dict)
        get_write_shard_metrics(fp, index_status_dict)

    now = datetime.datetime.now().strftime('%Y/%m/%d')
    s3file_name = (
        f'AWSLogs/{AWS_ID}/OpenSearch/metrics/{REGION}/{now}/{file_name}')
    print(f'INFO: Uploaded to s3://{BUCKET_NAME}/{s3file_name}')
    bucket.upload_file(f'/tmp/{file_name}', s3file_name)

    os.remove(f'/tmp/{file_name}')

    return {"statusCode": 200}


if __name__ == '__main__':
    lambda_handler(None, None)
