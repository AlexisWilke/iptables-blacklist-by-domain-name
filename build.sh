#!/bin/sh

rm -rf BUILD
mkdir BUILD
cd BUILD
cmake ..
make

# vim: ts=4 sw=4 et
