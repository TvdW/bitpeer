bitpeer
=======

Bitpeer is an experimental Bitcoin relay server. Its event-driven architecture makes it extremely fast, and it was designed to be very lightweight.

The target memory limit is 10MB for handling 1000 peers, plus 15 for the block indexes.


Features
========

* Transaction relaying using a small in-memory pool
* Block relaying using disk-based block storage
* Handling several thousands of peers, if the network allows it
* Extremely lightweight (below 25MB memory usage up to 1000 peers)
* Extremely fast (using `sendfile` support and a lot of caching)
* Address relaying (`getaddr` coming soon)


Usage
=====

    ./bitpeer <listen_port> <public_ip[:port]> -n <seed_addr[:port]>

    ./bitpeer 8333 1.2.3.4 -n 5.6.7.8:8333


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

The code currently only requires the `libevent2` and `openssl` libraries. Kernel support for IPv4 to IPv6 mapping is also required.