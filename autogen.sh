#!/bin/sh
git submodule update --init --recursive
exec autoreconf -fis
