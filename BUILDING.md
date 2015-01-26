VigorTLS Building Instructions
==============================
------------------------------

Building in a *NIX environment
------------------------------
----
## Requirements
* CMake 2.8.8+
* GCC or Clang
* Perl

----
## Building
	$ mkdir build
	$ cd build
	$ cmake ..
	$ make

------------------------------

Building in a Windows environment
---------------------------------
----
## Requirements
* CMake 2.8.8+
* Visual Studio 2013+ (Might work on older versions [NOT TESTED])
* MinGW/MSYS environment
* ActiveState Perl
* Yasm

----
## Building
	Launch MSYS shell with vcvarsall.bat
	$ mkdir build
	$ cmake -G"NMake Makefiles" ..
	$ nmake -f Makefile
