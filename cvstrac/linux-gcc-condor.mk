#!/usr/bin/make
#
#### The toplevel directory of the source tree.
#
SRCDIR = ../cvstrac

#### C Compiler and options for use in building executables that
#    will run on the platform that is doing the build.
#
# -Iinclude ??
BCC = gcc -g -O0 -Wall -Iinclude

#### The suffix to add to executable files.  ".exe" for windows.
#    Nothing for unix.
#
E =

#### C Compile and options for use in building executables that 
#    will run on the target platform.  This is usually the same
#    as BCC, unless you are cross-compiling.
#
#TCC = gcc -O6
TCC = $(BCC)
#TCC = gcc -g -O0 -Wall -fprofile-arcs -ftest-coverage

#### Extra arguments for linking against SQLite
#
LIBSQLITE = lib/libsqlite3.a -lcrypt -lm -ldl -lpthread

#### Installation directory
#
INSTALLDIR = ./


# You should not need to change anything below this line
###############################################################################
include $(SRCDIR)/main.mk
