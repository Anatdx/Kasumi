# prctl benchmark

`prctl_bench` measures the latency distribution of the removed Kasumi `prctl`
control path from an unprivileged process. It is kept as a regression test and
refuses to run as root unless explicitly overridden for development.

The benchmark measures four raw syscalls in rotating order:

- `getpid`, as a small syscall reference
- `prctl(PR_GET_DUMPABLE)`, as a valid native `prctl`
- `prctl(0x48020)`, as an unknown-option control
- `prctl(0x48021)`, as the removed Kasumi magic option

The strongest signal is a repeated A/B/A comparison with the module unloaded,
loaded, and unloaded again. `magic_delta` is a paired comparison between the
removed Kasumi option and the neighboring unknown option within one run. After
the control path removal, both options must follow the same native `prctl`
path and their paired delta should collapse to noise.

## Build

With an Android NDK compiler:

```sh
make CC="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android29-clang"
```

For a standalone static binary using a GNU cross compiler:

```sh
make CC=aarch64-linux-gnu-gcc STATIC=1
```

The output is `out/prctl_bench`.

## Run

Push and run it as the regular ADB shell user, without `su`:

```sh
adb push out/prctl_bench /data/local/tmp/prctl_bench
adb shell chmod 0755 /data/local/tmp/prctl_bench
adb shell /data/local/tmp/prctl_bench -c 4 -n 30000 -b 64
```

Options:

- `-n N`: number of measured blocks per case; default `20000`
- `-b N`: syscalls per measured block; default `64`
- `-w N`: warm-up calls per case; default `20000`
- `-c CPU`: pin the process to one allowed CPU
- `-r PATH`: write per-block samples to a CSV file
- `--drop-uid UID`: when launched by a root ADB daemon, clear supplementary
  groups and permanently drop to this nonzero UID before measuring
- `--allow-root`: development-only override of the non-root check

For a root ADB daemon, use the explicit drop instead of `--allow-root`:

```sh
adb shell /data/local/tmp/prctl_bench --drop-uid 2000 -n 30000 -b 64
```

This exercises Kasumi's non-root `current_uid()` path, although the process
keeps its original SELinux domain. Use an APK or a debuggable package with
`run-as` if the SELinux domain is also part of the experiment.

Use the same CPU, sample count, batch size, device state, and thermal state for
every A/B/A run. Repeat each state several times. Compare the `prctl` rows
between states; do not treat the `getpid` ratio alone as proof because the
native syscall bodies differ.
