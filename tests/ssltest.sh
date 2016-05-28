#!/bin/sh

set -e
PATH=$1:$2:$PATH
export PATH

testssl $2/data/server.pem $2/data/server.pem $2/data/ca.pem $1/../tests $2/data/serverinfo.pem
