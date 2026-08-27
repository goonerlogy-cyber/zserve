# zserve

A single-binary static file server with directory listing and a live
terminal request dashboard. Zig standard library only, no dependencies.
A real `python -m http.server` replacement.

## Build

```
zig build
```

Pinned to Zig 0.16.

## Usage

```
./zig-out/bin/zserve [root] [port]
```

Defaults to `.` and port 8080. Serves static files with content-type
guessed from extension, renders a directory listing for any path that
resolves to a directory, and redraws a live dashboard (total requests,
bytes served, status code breakdown, top 8 requested paths) after every
request.

`ctrl+c` to quit.

## Real bug found in testing: getdents64's name offset

`listDir` parses raw `getdents64(2)` output by hand. The kernel's
`dirent64` record is `ino:u64, off:u64, reclen:u16, type:u8`, then the
null-terminated name starts immediately after, 19 bytes in, packed, no
padding. The first version used `@sizeOf(linux.dirent64)` as that offset
instead of a hardcoded 19. `@sizeOf` on the Zig-side `extern struct`
reports 24, because Zig rounds the struct's total size up to its largest
field's alignment (8, for the `u64` members). Reading the name from that
offset pulled 5 bytes of padding garbage in before the real name, so
every directory listing rendered garbled filenames instead of real ones.
Fixed by hardcoding the actual on-wire kernel ABI offset (19) instead of
trusting the host struct's padded size. Caught by hand while testing the
running server against a real curl request, not by a unit test, since the
bug only manifests with the raw byte offsets the kernel actually writes.

## Real bug found in testing: percent-encoded path traversal

`safeJoin` originally rejected any URL path containing a literal `..`
before percent-decoding it. A request for `/etc/passwd` encoded as
`%2e%2e/%2e%2e/etc/passwd` doesn't contain a literal `..` in the raw
request, it only appears after decoding, so it sailed straight past that
check and produced a real path traversal. Caught by a unit test written
specifically for the percent-encoded case (a plain literal-`..` test
alone would never have caught this). Fixed by moving the `..` check to
run on the decoded path, not the raw one.

## Scope cuts from the original idea

On-the-fly gzip compression stayed out of this build. Zig's
`std.compress.flate` exists and works, but it's built against a newer
`std.Io.Writer`-based streaming API that's still actively shifting in
this Zig version, along with `std.fs` itself (both `readCmdlineArgs` and
all file/directory I/O in this project go through raw Linux syscalls
directly instead, for the same reason). Wiring compression through that
churn wasn't worth the risk for this pass. Concurrent request handling
(a worker thread per connection, feeding a shared mutex-protected stats
struct) also stayed out, this version handles one request at a time on
the accept loop and redraws the dashboard after each one, both real
scope cuts, not oversights, and both fit inside the doc's own MVP line.

## License

See [LICENSE](LICENSE).
