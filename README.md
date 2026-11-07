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
- Terminal size, raw-mode handling and optional native-console key conversion.
- Filename globbing and temporary-file creation.
- TLS client connections with a provider interface and a descriptor adapter
  for event loops. The supplied provider uses the Linux I/O server's optional
  TLS service.
- SSH sessions with a provider interface, terminal resizing, password and
  private-key authentication, and a native `ssh` command. The supplied provider
  uses the Linux I/O server's optional SSH service.

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
Host-offloaded SSH requires `IOS_SSH=1` and libssh2 on the I/O-server host.

The common builder produces the archive, headers and runtime helpers without
requiring a distribution checkout. Select the CPU explicitly and use separate
work directories for different targets:

```sh
python3 build.py --cpu t425 --work work/t425 \
  --sdk /path/to/sdk/prod/TRAN --asm /path/to/sdk/host/bin/asm \
  --helios-ng /path/to/Helios-NG
```

Use `--cpu t800` for T800/T805 builds. `--toolchain` selects llvm-t800;
`--tests` also compiles the native regression programs. The matching Helios-NG
source supplies the private DNS resolver header used by the native adapter.
`build.py verify` with the same options checks the input fingerprint and all
staged files. CPU and test selection are part of that fingerprint.
The fingerprint includes the Clang executable selected by `hcc` and its
`HCC_*` environment settings. Compatibility header templates are under
`templates/compat`; the builder stages them beside the native SDK headers.

The staged SDK is `WORK/stage`. Use headers in this
order:

1. `include/helios-unix/compat` for the opt-in compatibility definitions.
2. `include/helios-unix` for `<helios/unix/...>` interfaces.
3. The native Helios SDK's `include` directory.

Link `helios-unix.lib` before `bsd.lib`, `c.lib` and `helios.lib`. The generated
`lib/helios-unix-flags.json` records include order and compiler definitions.
Install the resolver helper at `/helios/lib/hu-resolve` for asynchronous lookup.
The distribution stages the SSH client at `/helios/bin/ssh`; use
`ssh user@host` or `ssh -p 2222 user@host command`.
Use the same header profile for the application and its dependencies.

## Manuals

Start with `man 7 helios-unix`. The section 3 pages cover `hu_spawn`,
`hu_channel`, `hu_poll`, `getaddrinfo`, `hu_resolve`, `hu_terminal`, `hu_tls`,
`hu_tls_fd`, `glob` and `mkstemp`, including examples and ownership rules.
`ssh(1)` documents the client and `hu_ssh(3)` documents the session/provider API.
Individual function names work too, for example `man hu_tls_attach_fd`.
The distribution's manual build installs both source and preformatted pages
for the native `man` reader and Xman.

To read directly on a Unix host, run from this checkout:

```sh
man -M "$PWD/man" 7 helios-unix
man -M "$PWD/man" 3 hu_terminal_read
```

`make -C man install PREFIX=/usr/local` installs host manuals; `DESTDIR` is
supported for packaging. `make -C man check` checks all pages with groff.
To also compile the C examples against a staged SP2 SDK:

```sh
python3 man/check.py --clang /opt/llvm-t800/bin/clang \
  --sdk ../ktm-distribution/work/sdk/prod/TRAN \
  --stage ../ktm-distribution/work/compat/stage
```

## Tests

Run the host contract tests with a C compiler, Python 3 and AddressSanitizer/
UndefinedBehaviorSanitizer support:

```sh
python3 tests/host/run_tls.py
python3 tests/host/run_glob.py
python3 tests/host/run_poll.py
python3 tests/host/run_ssh.py
python3 tests/host/run_ssh_terminal.py
python3 tests/test_build.py
```

The TLS test uses a mock provider to check the API contract; it does not test
cryptography. Native test programs are in `tests/` and are built alongside
the archive. They require Helios to exercise task, descriptor and channel
behaviour. `tests/check_sdk.py` checks the generated header profile with hcc.

## Licence

GPL version 3; see [LICENSE](LICENSE). Source-file copyright and attribution
notices apply where present.
