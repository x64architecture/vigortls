#!/bin/sh

set -e
PATH=../../build/apps:$PATH
export PATH

topdir=../../tests

$topdir/testssl $topdir/data/server.pem $topdir/data/server.pem $topdir/data/ca.pem
