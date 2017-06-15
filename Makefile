BUILD_UP=`pwd`/../build

all: build/gittrac

clean:
	cd sqlite && make clean ; /bin/true
	rm sqlite/Makefile ; /bin/true
	rm -rf build ; /bin/true

build:
	mkdir build

run: build/gittrac
	build/gittrac server 8080 data CondorWiki

# SQLite
sqlite/Makefile: sqlite/configure
	cd sqlite && env CFLAGS="-Os" ./configure --prefix=$(BUILD_UP)

sqlite/.libs/libsqlite3.a: sqlite/Makefile
	cd sqlite && make

build/lib/libsqlite3.a: sqlite/.libs/libsqlite3.a
	cd sqlite && make install

# CVSTrac

build/Makefile: cvstrac/linux-gcc-condor.mk build
	cp cvstrac/linux-gcc-condor.mk build/Makefile

build/gittrac: build/Makefile build/lib/libsqlite3.a
	cd build && make APPNAME=gittrac
