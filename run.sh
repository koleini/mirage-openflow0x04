#!/usr/bin/env bash

eval `opam config env`
env ADDR=dhcp NET=direct mirage config --xen
sed -i "s/-pkgs/-I lib -I frenetic-lib -pkgs/" Makefile
make
