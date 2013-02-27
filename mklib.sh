#!/bin/bash
gcc -I/opt/local/include -I/Library/Frameworks/Python.framework/Versions/3.3/include/python3.3m -shared -o sslsign.so -Wall -fpic signmodule.c sslsign.c /opt/local/lib/libssl.a /opt/local/lib/libcrypto.a /opt/local/lib/libz.a /Library/Frameworks/Python.framework/Versions/3.3/lib/libpython3.3m.dylib

