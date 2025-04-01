#!/bin/bash

set -e
cd $(dirname $0)

if [[ $# -ne 3 ]] && [[ $# -ne 4 ]] ;  then
  echo "Usage: $0 <name> <bucket> <python> <profile>"
  echo ''
  echo 'Options:'
  echo '  name           Name used as prefix for resources'
  echo '  bucket         S3 bucket URI used to store source code (format: s3://<bucket>/<prefix>)'
  echo '  python         Python version to use'
  echo '  profile        Use a specific AWS profile from your credential file'
  exit 1
fi

NAME=$1
BUCKET=$2
if [[ $BUCKET =~ s3://([^/]+)/(.+) ]]; then
  BUCKET=${BASH_REMATCH[1]}
  PREFIX=${BASH_REMATCH[2]}
else
  echo 'Invalid bucket format. Must be s3://<bucket>/<prefix>'
  exit 1
fi
PYTHON_VERSION=$3
if [[ $# -eq 4 ]] ; then
  export AWS_PROFILE=$4
fi

echo 'Packaging requirements...'
rm -rf target

pip3 install -r requirements.txt \
  --platform=manylinux2014_x86_64 \
  --python-version $PYTHON_VERSION \
  --only-binary :all: \
  --implementation cp \
  --target target/python/lib/python$PYTHON_VERSION/site-packages

(cd target && zip -r requirements.zip ./python)

trap "rm -f packaged-stack.yaml" EXIT

aws cloudformation package \
  --template stack.yaml \
  --s3-bucket $BUCKET \
  --s3-prefix $PREFIX \
  --output-template-file packaged-stack.yaml

aws cloudformation deploy \
  --template-file packaged-stack.yaml \
  --stack-name $NAME \
  --capabilities 'CAPABILITY_NAMED_IAM'
