#!/bin/bash

set -e
cd $(dirname $0)

if [[ $# -ne 1 ]] ;  then
  echo "Usage: $0 <python>"
  echo ''
  echo 'Options:'
  echo '  python         Python version to use'
  exit 1
fi

PYTHON_VERSION=$1

rm -rf target
mkdir -p target/python/lib/python$PYTHON_VERSION/site-packages target/bin target/lib

docker run --rm -v $(pwd):/tmp -w /tmp/target amazonlinux:2023 sh -c '
  yum install -y openssl\
     && cp /usr/bin/openssl bin/openssl \
     && cp /usr/lib64/libbz2.so.1 lib \
     && cp /usr/lib64/libssl.so.3 lib \
     && cp /usr/lib64/libcrypto.so.3 lib
'

pip3 install -r requirements.txt \
  --platform=manylinux2014_x86_64 \
  --python-version $PYTHON_VERSION \
  --only-binary :all: \
  --implementation cp \
  --target target/python/lib/python$PYTHON_VERSION/site-packages

cd target
zip -r layer.zip ./python ./lib ./bin
