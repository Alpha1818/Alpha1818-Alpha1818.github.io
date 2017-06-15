#!/usr/bin/make
#
#### Windows libraries paths
INCDIRSQLITE = libs/sqlite3/include
LIBDIRSQLITE = libs/sqlite3/lib
INCREGEX = libs/regex-0.12
LIBREGEX = libs/regex-0.12/regex.o
LIBCRYPT = libcrypt.dll

#### The toplevel directory of the source tree.
#
SRCDIR = .

#### C Compiler and options for use in building executables that
#    will run on the platform that is doing the build.
#
BCC = gcc -g -O2

#### The suffix to add to executable files.  ".exe" for windows.
#    Nothing for unix.
#
E = .exe

#### C Compile and options for use in building executables that
#    will run on the target platform.  This is usually the same
#    as BCC, unless you are cross-compiling.
#
#TCC = gcc -O6
#TCC = gcc -g -O0 -Wall -Iwin32 -I$(INCDIRSQLITE) -I$(INCREGEX) -DWIN32
TCC = gcc -Os -Wall -Iwin32 -I$(INCDIRSQLITE) -I$(INCREGEX) -DWIN32
#TCC = gcc -g -O0 -Wall -fprofile-arcs -ftest-coverage -Iwin32 -I$(INCDIRSQLITE) -DWIN32

#### Extra arguments for linking against SQLite
#
LIBSQLITE = -L$(LIBDIRSQLITE) -lsqlite3 -lm -lws2_32 $(LIBCRYPT) $(LIBREGEX) -Wl,-s
#LIBSQLITE = -L$(LIBDIRSQLITE) -lsqlite3 -lm -lws2_32 $(LIBCRYPT) $(LIBREGEX)

#### Installation directory
#
INSTALLDIR = /var/www/cgi-bin


# You should not need to change anything below this line
###############################################################################
include $(SRCDIR)/main.mk
