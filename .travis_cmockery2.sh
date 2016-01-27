#!/bin/sh

git clone -b v1.3.9 https://github.com/lpabon/cmockery2.git
cd cmockery2
./autogen.sh || exit 1
./configure --prefix=/usr || exit 1
make || exit 1
sudo make install || exit 1
cd ..
rm -rf cmockery2

git clone -b cpp-1.3.0 https://github.com/msgpack/msgpack-c.git
cd msgpack-c
./bootstrap || exit 1
./configure --prefix=/usr || exit 1
make || exit 1
sudo make install || exit 1
cd ..
rm -rf msgpack-c

