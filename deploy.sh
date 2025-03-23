#!/bin/bash

set -e
cd $(dirname $0)

if [[ $# -ne 2 ]] && [[ $# -ne 3 ]] ;  then
  echo "Usage: $0 <name> <bucket> <profile>"
  echo ''
  echo 'Options:'
  echo '  name           Name used as prefix for resources'
  echo '  bucket         S3 bucket name used to store source code'
  echo '  profile        Use a specific AWS profile from your credential file'
  exit 1
fi

NAME=$1
BUCKET=$2
if [[ $# -eq 3 ]] ; then
  export AWS_PROFILE=$3
fi

trap "rm -f packaged-stack.yaml" EXIT

aws cloudformation package \
  --template stack.yaml \
  --s3-bucket $BUCKET \
  --s3-prefix $NAME \
  --output-template-file packaged-stack.yaml

aws cloudformation deploy \
  --template-file packaged-stack.yaml \
  --stack-name "$NAME-stack" \
  --parameter-overrides Name=$NAME \
  --capabilities 'CAPABILITY_NAMED_IAM'
