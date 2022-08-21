#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

export layer_name="AWSDataWrangler-Python38"
export layer_zip="awswrangler-layer-2.16.1-py3.8.zip"
export wrangler_ver="2.16.1"
export lambda_name="aes-siem-es-loader"

layer_arn=$(aws lambda list-layer-versions --layer-name $layer_name --query "LayerVersions[0].LayerVersionArn" --output text)
if [[ "$layer_arn" == "None" ]]; then
    echo "download aws-data-wrangler"
    aws lambda publish-layer-version --layer-name "$layer_name" --zip-file "fileb://$layer_zip" --compatible-runtimes python3.8
    aws s3 cp "s3://aws-data-wrangler-public-artifacts/releases/$wrangler_ver/$layer_zip" .
    layer_arn=$(aws lambda list-layer-versions --layer-name $layer_name --query "LayerVersions[0].LayerVersionArn" --output text)
fi
lambda_layers="$(aws lambda get-function --function-name $lambda_name --query "Configuration.Layers[*].Arn" --output text)"
has_wrangler=$(echo "$lambda_layers" |grep $layer_name)
if [[ -z "$has_wrangler" ]]; then
    echo 'added the layer to lambda function'
    aws lambda update-function-configuration --function-name "$lambda_name" --layers "$lambda_layers" "$layer_arn"
fi
