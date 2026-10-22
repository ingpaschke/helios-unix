Resident ABI requirements

The archive requires Helios Posix version 1001. The resident library owns
the descriptor and child tables used by hu_spawn_native. Applications include
helios/unix/spawn.h, which uses the SDK's installed hu-spawn.h declaration.

hu_channel uses the native FIFO server. Files under backend/ are excluded
from the active archive build.
