# oncep

TCP port scanner with per-port confidence and an ETA, by [Mexsic](https://mexsic.io). It completes a TCP connect. It does not need root. It runs on macOS and Linux.

## Build

Rust 1.75 or newer. Install it from <https://rustup.rs> if you do not have it.

```bash
cargo build --release
./target/release/oncep --help
```

The binary is `target/release/oncep`. On macOS it links against the system. On Linux it links against that machine's glibc. If another Linux does not share that glibc, use the image below: the binary is built inside Debian bookworm and runs on that base.

The same command works on Apple Silicon and on Intel Macs. The binary matches the architecture you compile on.

## Docker

The image builds the binary and leaves it on Debian bookworm. It works on Linux amd64 and arm64. The build follows your Docker architecture.

```bash
docker build -t oncep .
docker run --rm oncep --help
docker run --rm oncep -q -p 22,80,443 example.com
```

To publish both architectures:

```bash
docker buildx build --platform linux/amd64,linux/arm64 -t oncep .
```

## Usage

```bash
oncep -p 1-1024 example.com
oncep -q -F json -o result.json 10.0.0.1
```

A name is resolved once, at startup. The line `name → ip` goes to stderr. If the resolver does not answer, the process fails after 5 seconds.

Each port has a budget of 3 attempts. A completed connection or a refusal finishes the port on the first try. A silence continues until it crosses `--min-confidence` (0.95), once the host has already answered, or until the 3 attempts are spent. `--insist` always spends all 3.

The progress line goes to stderr. `-q` turns off the banner and the progress line. `-F text` is the default and prints open ports only. `txt` and `json` print every port. `-o` writes the result to a file.
