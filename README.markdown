Ccnet is a framework for writing networked applications in C. It
provides the following basic services:

1. Peer identification
2. Connection Management
3. Service invocation
4. Message sending

In ccnet network, there are two types of nodes, i.e., client and server.
Server has the following functions:

1. User management
2. Group management

This repository is the Ccnet server.

Dependency
==========

The following packages are required to build ccnet:

    valac >= 0.8
    libsearpc
    ccnet
    libmysqlclient-dev for compiling ccnet server

Compile
=======

To compile the client components, just

    ./autogen.sh && ./configure && make && make install

In Mac OS, use

    LDFLAGS="-L/opt/local/lib -L/usr/local/mysql/lib -Xlinker -headerpad_max_install_names" ./configure

License
=======

Ccnet server is published under AGPLv3. See LICENSE.txt for details.
