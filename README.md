# helios-unix

An opt-in Unix compatibility library for native Helios applications. It uses
Helios descriptors, memory allocation and resident libraries and is intended
for programs running on Transputers.

## Facilities

- Native program launching with input/output redirection and processor selection.
- IPv4 `getaddrinfo`, `getnameinfo` and asynchronous name lookup.
- Bounded FIFO channels for communication between tasks, including tasks on
  different processors.
- `hu_poll` readiness for sockets, FIFO channels and regular files.
- Terminal size, raw-mode handling and terminal-input decoding.
- Filename globbing and temporary-file creation.
- TLS client connections with a provider interface and a descriptor adapter
  for event loops. The supplied provider uses the Linux I/O server's optional
  TLS service.

The library does not implement Unix `fork`, pthreads or shared memory, and
is not a complete POSIX implementation. Calls use the application thread.
Task spawning creates a new Helios task; descriptors in separate tasks do
not share cached status or file positions. The TLS provider interface supports
byte transports, but no native Transputer cryptographic engine is included.
See [the API contracts](docs/contracts.txt) for ownership, error handling and
individual interface limits, and [capabilities.json](capabilities.json) for
the machine-readable feature profile.

## Build and use

Requirements are a Helios-NG 1.31-SP2 SDK with resident Posix version 1001 and the
matching `hu-spawn.h`, the llvm-t800 compiler, and the Helios assembler.
FIFO channels require the native FIFO server with readiness support.
Host-offloaded TLS additionally requires an I/O server built with `IOS_TLS=1`.

The distribution build recipe produces the archive, headers and resolver
helper. With sibling `helios-unix`, `Helios-NG` and `ktm-distribution`
checkouts, and the SDK built under `ktm-distribution/work/sdk`, run from
their parent directory:

```sh
HELIOS_NG_ROOT="$PWD/Helios-NG" python3 ktm-distribution/build_compat.py
```

The staged SDK is `ktm-distribution/work/compat/stage`. Use headers in this
order:

1. `include/helios-unix/compat` for the opt-in compatibility definitions.
2. `include/helios-unix` for `<helios/unix/...>` interfaces.
3. The native Helios SDK's `include` directory.

Link `helios-unix.lib` before `bsd.lib`, `c.lib` and `helios.lib`. The generated
`lib/helios-unix-flags.json` records include order and compiler definitions.
Install the resolver helper at `/helios/lib/hu-resolve` for asynchronous lookup.
Use the same header profile for the application and its dependencies.

## Tests

Run the host contract tests with a C compiler, Python 3 and AddressSanitizer/
UndefinedBehaviorSanitizer support:

```sh
python3 tests/host/run_tls.py
python3 tests/host/run_glob.py
python3 tests/host/run_poll.py
```

The TLS test uses a mock provider to check the API contract; it does not test
cryptography. Native test programs are in `tests/` and are built alongside
the archive. They require Helios to exercise task, descriptor and channel
behaviour. `tests/check_sdk.py` checks the generated header profile with hcc.

## Licence

GPL version 3; see [LICENSE](LICENSE). Source-file copyright and attribution
notices apply where present.
