#!/bin/bash
#
# This assumes all of the OS-level configuration has been completed and git repo has already been cloned
#
# This script should be run from the repo's deployment directory
# cd deployment
# ./build-s3-dist.sh source-bucket-base-name solution-name version-code
#
# Paramenters:
#  - source-bucket-base-name: Name for the S3 bucket location where the template will source the Lambda
#    code from. The template will append '-[region_name]' to this bucket name.
#    For example: ./build-s3-dist.sh solutions my-solution v1.0.0
#    The template will then expect the source code to be located in the solutions-[region_name] bucket
#
#  - solution-name: name of the solution for consistency
#
#  - version-code: version of the package

# Check to see if input has been provided:
if [ -z "$1" ]; then
    echo "Please provide the base source bucket name, trademark approved solution name and version where the lambda code will eventually reside."
    echo "For example: ./build-s3-dist.sh template-output-bucket-name"
    exit 1
fi

shopt -s expand_aliases
if [ -e /usr/local/bin/gsed ]; then
    alias sed=/usr/local/bin/gsed
else
    alias sed=/usr/bin/sed
fi

# Get reference for all important folders
template_dir="$PWD"
template_dist_dir="$template_dir/global-s3-assets"
build_dist_dir="$template_dir/regional-s3-assets"
source_dir="$template_dir/../source"

echo "------------------------------------------------------------------------------"
echo "[Init] Clean old dist, node_modules and bower_components folders"
echo "------------------------------------------------------------------------------"
echo "rm -rf $template_dist_dir"
rm -rf $template_dist_dir
echo "mkdir -p $template_dist_dir"
mkdir -p $template_dist_dir
echo "rm -rf $build_dist_dir"
rm -rf $build_dist_dir
echo "mkdir -p $build_dist_dir"
mkdir -p $build_dist_dir

echo "------------------------------------------------------------------------------"
echo "[Packing] Templates"
echo "------------------------------------------------------------------------------"
echo "cp $template_dir/*.template $template_dist_dir/"
cp $template_dir/*.template $template_dist_dir/
echo "Updating code source bucket in template with $1"
replace="s/%%BUCKET_NAME%%/$1/g"

if [ "$(uname)" == 'Darwin' ]; then
# Command for MacOS('sed -i' in MacOS needs extension as parameter)
    echo "sed -i '' $replace $template_dist_dir/*.template"
    sed -i '' $replace $template_dist_dir/*.template
else
    echo "sed -i $replace $template_dist_dir/*.template"
    sed -i $replace $template_dist_dir/*.template
fi

echo "------------------------------------------------------------------------------"
echo "Copy Lambda function"
echo "------------------------------------------------------------------------------"
cd $source_dir/lambda/
pwd
ls *.zip
if [ ! -d  $build_dist_dir/assets ]; then
    mkdir -p $build_dist_dir/assets/
fi
cp -f *.zip $build_dist_dir/assets/

echo "------------------------------------------------------------------------------"
echo "Pack and Copy saved objects of Kibana"
echo "------------------------------------------------------------------------------"
cd $source_dir/saved_objects
zip -r ../saved_objects.zip *
if [ ! -d  $template_dist_dir/assets ]; then
    mkdir -p $template_dist_dir/assets/
fi
mv ../saved_objects.zip $template_dist_dir/assets/
