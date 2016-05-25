#!/bin/sh

set -e
PATH=$1:$2:$PATH
export PATH

tocsp $2
