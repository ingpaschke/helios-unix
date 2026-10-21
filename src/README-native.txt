Resident additions live in hng-sp1/posix and are compiled by build_posix.py.
They are not ordinary archive members: they need the existing descriptor
and child tables. hu_spawn_native is appended to the resident export table;
all prior slots retain their indices. Its import requires Posix version 1001.
The authoritative spawn ABI header is hng-sp1/include/hu-spawn.h; the
helios/unix/spawn.h adapter includes the installed copy of that header.
backend/pipe-experimental.* is historical experimental code, not the active
channel implementation. hu_channel uses the native FIFO server.
