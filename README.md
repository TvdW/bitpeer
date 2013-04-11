bitpeer
=======

Bitpeer is an experimental Bitcoin relay server. Its event-driven architecture makes it extremely fast, and it was designed to be very lightweight.

The target memory limit is 10MB for handling 1000 peers, plus 15 for the block indexes.


Usage
=====

    ./bitpeer [listen_port] [announce_addr:port] [seed_addr:port]

    ./bitpeer 8333 1.2.3.4:8333 5.6.7.8:8333

Some settings are available in `bitpeer.c`.


Requirements
============

The code currently only requires `libevent2` and `openssl`.


Caution
=======

This is experimental software, and while it is currently very fast at relaying certain commands, other commands are not yet implemented. Until block relaying is implemented, the relay should not be used on a large scale, as that could be potentially very bad for the bitcoin network.
