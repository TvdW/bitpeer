bitpeer
=======

Bitpeer is an experimental Bitcoin relay server. Its event-driven architecture makes it extremely fast, and it was designed to be very lightweight.

The target memory limit is 10MB for handling 1000 peers, plus 15 for the block indexes.


Features
========




Usage
=====

    ./bitpeer [listen_port] [announce_addr:port] [seed_addr:port]

    ./bitpeer 8333 1.2.3.4:8333 5.6.7.8:8333

Some settings are available in `bitpeer.c`.


Installation
============

When building from git:

	autoreconf -i
	./configure
	make

When building from a tarball:

	./configure
	make


Requirements
============

The code currently only requires `libevent2` and `openssl`.
