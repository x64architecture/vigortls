VigorTLS
========

VigorTLS is a fork of OpenSSL developed by Kurt Cancemi.

[![Build Status](https://secure.travis-ci.org/vigortls/vigortls.png)](http://travis-ci.org/vigortls/vigortls)

Goal
====

The goal of the VigorTLS Project is to improve the original OpenSSL codebase
by using modern C features, removing support for ancient operating systems
that are rarely used/hard to support, replacing potentially dangerous
functions/calls with secure ones, and replacing the unreadable coding style.

Build instructions
==================

	$ mkdir build
	$ cd build
	$ cmake ..
	$ make

Currently tested operating systems
==================================

* Linux
* Mac OS X
