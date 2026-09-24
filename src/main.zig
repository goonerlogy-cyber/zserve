const std = @import("std");
const linux = std.os.linux;
const http = @import("httpserver.zig");
const fsutil = @import("fsutil.zig");

fn checkErrno(rc: usize) !usize {
    const signed: isize = @bitCast(rc);
    if (signed < 0) return error.SyscallFailed;
    return rc;
}

const COL_RESET = "\x1b[0m";
const COL_ACCENT = "\x1b[38;2;111;232;158m";
const COL_SUBTLE = "\x1b[38;2;92;92;112m";
const COL_BOLD = "\x1b[1m";
const COL_2XX = "\x1b[38;2;111;232;158m";
const COL_3XX = "\x1b[38;2;120;180;240m";
const COL_4XX = "\x1b[38;2;232;181;82m";
const COL_5XX = "\x1b[38;2;220;90;90m";

var should_stop: bool = false;

fn handleSigint(sig: linux.SIG) callconv(.c) void {
    _ = sig;
    should_stop = true;
}

fn installSigintHandler() void {
    const act = linux.Sigaction{
        .handler = .{ .handler = &handleSigint },
        .mask = std.mem.zeroes(linux.sigset_t),
        .flags = 0,
    };
    _ = linux.sigaction(linux.SIG.INT, &act, null);
}

fn readCmdlineArgs(buf: []u8, out: [][]const u8) [][]const u8 {
    const fd_rc = linux.open("/proc/self/cmdline", .{ .ACCMODE = .RDONLY }, 0);
    const fd: i32 = @intCast(checkErrno(fd_rc) catch return out[0..0]);
    defer _ = linux.close(fd);

    const n = checkErrno(linux.read(fd, buf.ptr, buf.len)) catch return out[0..0];

    var count: usize = 0;
    var it = std.mem.splitScalar(u8, buf[0..n], 0);
    var idx: usize = 0;
    while (it.next()) |arg| {
        if (arg.len == 0) continue;
        if (idx > 0 and count < out.len) {
            out[count] = arg;
            count += 1;
        }
        idx += 1;
    }
    return out[0..count];
}

pub const LogEntry = struct {
    timestamp_sec: i64 = 0,
    client_ip: [32]u8 = std.mem.zeroes([32]u8),
    client_ip_len: usize = 0,
    method: [8]u8 = std.mem.zeroes([8]u8),
    method_len: usize = 0,
    path: [64]u8 = std.mem.zeroes([64]u8),
    path_len: usize = 0,
    status: u16 = 0,
    bytes_sent: u64 = 0,
};

pub const LogRing = struct {
    entries: [10]LogEntry = std.mem.zeroes([10]LogEntry),
    head: usize = 0,
    count: usize = 0,

    pub fn append(self: *LogRing, entry: LogEntry) void {
        self.entries[self.head] = entry;
        self.head = (self.head + 1) % self.entries.len;
        if (self.count < self.entries.len) {
            self.count += 1;
        }
    }
};

var log_ring = LogRing{};

fn parseClientIp(addr: *const linux.sockaddr, buf: []u8) []const u8 {
    if (addr.family == linux.AF.INET) {
        const in_addr: *const linux.sockaddr.in = @ptrCast(@alignCast(addr));
        const ip_bytes: [4]u8 = @bitCast(in_addr.addr);
        return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3] }) catch "127.0.0.1";
    }
    return "127.0.0.1";
}

fn printHelp() void {
    std.debug.print(
        \\zserve - high-performance single-binary static HTTP file server
        \\
        \\Usage:
        \\  zserve [directory] [port]
        \\  zserve --help, -h
        \\
        \\Options:
        \\  directory   Root folder to serve static files from (default: .)
        \\  port        TCP port to listen on (default: 8080)
        \\
        \\Features:
        \\  • Zero-copy sendfile(2) streaming for high throughput
        \\  • HTTP Range requests (206 Partial Content) & HEAD method support
        \\  • Responsive web directory listing UI with file stats & breadcrumbs
        \\  • Clean terminal request dashboard with real-time log buffer
        \\
    , .{});
}

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var cmdline_buf: [1024]u8 = undefined;
    var args_storage: [8][]const u8 = undefined;
    const args = readCmdlineArgs(&cmdline_buf, &args_storage);

    if (args.len > 0) {
        if (std.mem.eql(u8, args[0], "-h") or std.mem.eql(u8, args[0], "--help")) {
            printHelp();
            return;
        }
    }

    const root: []const u8 = if (args.len > 0) args[0] else ".";
    const port: u16 = if (args.len > 1) std.fmt.parseInt(u16, args[1], 10) catch 8080 else 8080;

    installSigintHandler();

    const sock_rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0);
    const sock: i32 = @intCast(try checkErrno(sock_rc));
    defer _ = linux.close(sock);

    var opt: i32 = 1;
    _ = linux.setsockopt(sock, linux.SOL.SOCKET, linux.SO.REUSEADDR, std.mem.asBytes(&opt), @sizeOf(i32));

    const addr = linux.sockaddr.in{
        .port = std.mem.nativeToBig(u16, port),
        .addr = 0,
    };
    const bind_rc = linux.bind(sock, @ptrCast(&addr), @sizeOf(linux.sockaddr.in));
    const bind_signed: isize = @bitCast(bind_rc);
    if (bind_signed < 0) {
        const errno: usize = @intCast(-bind_signed);
        if (errno == @intFromEnum(std.posix.E.ADDRINUSE)) {
            std.debug.print("{s}zserve{s}: port {d} is already in use, pick a different port or stop whatever's already listening on it\n", .{ COL_ACCENT, COL_RESET, port });
        } else {
            std.debug.print("{s}zserve{s}: could not bind to port {d} (errno {d})\n", .{ COL_ACCENT, COL_RESET, port, errno });
        }
        std.process.exit(1);
    }
    _ = try checkErrno(linux.listen(sock, 128));

    var stats = http.Stats{};

    std.debug.print("{s}zserve{s} serving {s}{s}{s} on {s}http://0.0.0.0:{d}{s}\n", .{
        COL_ACCENT, COL_RESET, COL_SUBTLE, root, COL_RESET, COL_ACCENT, port, COL_RESET,
    });

    var req_buf: [8192]u8 = undefined;

    while (!should_stop) {
        var client_addr: linux.sockaddr = undefined;
        var addr_len: linux.socklen_t = @sizeOf(linux.sockaddr);
        const accept_rc = linux.accept(sock, &client_addr, &addr_len);
        const signed: isize = @bitCast(accept_rc);
        if (signed < 0) {
            if (should_stop) break;
            continue;
        }
        const client: i32 = @intCast(accept_rc);
        defer _ = linux.close(client);

        var ip_buf: [32]u8 = undefined;
        const client_ip = parseClientIp(&client_addr, &ip_buf);

        handleConnection(allocator, client, root, &req_buf, &stats, client_ip) catch {};
        renderDashboard(&stats, root, port);
    }
}

fn recordLog(client_ip: []const u8, method: []const u8, path: []const u8, status: u16, bytes_sent: u64) void {
    var entry = LogEntry{
        .timestamp_sec = std.time.timestamp(),
        .status = status,
        .bytes_sent = bytes_sent,
    };
    const ip_len = @min(client_ip.len, entry.client_ip.len);
    @memcpy(entry.client_ip[0..ip_len], client_ip[0..ip_len]);
    entry.client_ip_len = ip_len;

    const m_len = @min(method.len, entry.method.len);
    @memcpy(entry.method[0..m_len], method[0..m_len]);
    entry.method_len = m_len;

    const p_len = @min(path.len, entry.path.len);
    @memcpy(entry.path[0..p_len], path[0..p_len]);
    entry.path_len = p_len;

    log_ring.append(entry);
}

fn handleConnection(allocator: std.mem.Allocator, client: i32, root: []const u8, req_buf: []u8, stats: *http.Stats, client_ip: []const u8) !void {
    const n_rc = linux.read(client, req_buf.ptr, req_buf.len);
    const n = try checkErrno(n_rc);
    if (n == 0) return;

    stats.requests_total += 1;

    const req = http.parseRequestLine(req_buf[0..n]) catch |err| {
        const st: u16 = if (err == http.ParseError.MethodNotAllowed) 405 else 400;
        try sendStatus(client, st, "");
        stats.recordStatus(st);
        recordLog(client_ip, "UNKNOWN", "/", st, 0);
        return;
    };

    stats.recordPath(req.path);

    const is_head = std.mem.eql(u8, req.method, "HEAD");

    var path_buf: [1024]u8 = undefined;
    const disk_path = http.safeJoin(&path_buf, root, req.path) orelse {
        try sendStatus(client, 403, "");
        stats.recordStatus(403);
        recordLog(client_ip, req.method, req.path, 403, 0);
        return;
    };

    var pathz_buf: [1024]u8 = undefined;
    const disk_pathz = std.fmt.bufPrintZ(&pathz_buf, "{s}", .{disk_path}) catch {
        try sendStatus(client, 500, "");
        stats.recordStatus(500);
        recordLog(client_ip, req.method, req.path, 500, 0);
        return;
    };

    const kind = fsutil.statKind(disk_pathz);
    switch (kind) {
        .missing => {
            try sendStatus(client, 404, "not found");
            stats.recordStatus(404);
            recordLog(client_ip, req.method, req.path, 404, 0);
        },
        .dir => {
            if (!std.mem.endsWith(u8, req.path, "/")) {
                var redirect_buf: [1024]u8 = undefined;
                const location = try std.fmt.bufPrint(&redirect_buf, "{s}/", .{req.path});
                try sendRedirect(client, 301, location);
                stats.recordStatus(301);
                recordLog(client_ip, req.method, req.path, 301, 0);
                return;
            }
            try serveDirListing(allocator, client, disk_pathz, req.path, stats, is_head, client_ip);
        },
        .file => {
            try serveFile(client, disk_pathz, stats, req.range_header, is_head, client_ip, req.method, req.path);
        },
        .other => {
            try sendStatus(client, 403, "");
            stats.recordStatus(403);
            recordLog(client_ip, req.method, req.path, 403, 0);
        },
    }
}

fn serveFile(client: i32, path: [:0]const u8, stats: *http.Stats, range_header: ?[]const u8, is_head: bool, client_ip: []const u8, method: []const u8, url_path: []const u8) !void {
    const file_size = fsutil.fileSize(path) catch {
        try sendStatus(client, 500, "stat error");
        stats.recordStatus(500);
        recordLog(client_ip, method, url_path, 500, 0);
        return;
    };

    const ctype = http.contentType(path);

    if (range_header) |r_hdr| {
        if (http.parseRangeHeader(r_hdr, file_size)) |range| {
            const start = range.start;
            const end = range.end orelse (if (file_size > 0) file_size - 1 else 0);
            const content_len = if (end >= start) (end - start + 1) else 0;

            var header_buf: [512]u8 = undefined;
            const header = try std.fmt.bufPrint(&header_buf, "HTTP/1.1 206 Partial Content\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nContent-Range: bytes {d}-{d}/{d}\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\n", .{ ctype, content_len, start, end, file_size });

            _ = linux.write(client, header.ptr, header.len);

            var sent_bytes: u64 = 0;
            if (!is_head and content_len > 0) {
                sent_bytes = fsutil.sendfileStream(client, path, start, content_len) catch 0;
            }

            stats.bytes_served += sent_bytes;
            stats.recordStatus(206);
            recordLog(client_ip, method, url_path, 206, sent_bytes);
            return;
        } else {
            var header_buf: [256]u8 = undefined;
            const header = try std.fmt.bufPrint(&header_buf, "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */{d}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", .{file_size});
            _ = linux.write(client, header.ptr, header.len);
            stats.recordStatus(416);
            recordLog(client_ip, method, url_path, 416, 0);
            return;
        }
    }

    var header_buf: [256]u8 = undefined;
    const header = try std.fmt.bufPrint(&header_buf, "HTTP/1.1 200 OK\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\n", .{ ctype, file_size });

    _ = linux.write(client, header.ptr, header.len);

    var sent_bytes: u64 = 0;
    if (!is_head and file_size > 0) {
        sent_bytes = fsutil.sendfileStream(client, path, 0, file_size) catch 0;
    }

    stats.bytes_served += sent_bytes;
    stats.recordStatus(200);
    recordLog(client_ip, method, url_path, 200, sent_bytes);
}

fn serveDirListing(allocator: std.mem.Allocator, client: i32, disk_path: [:0]const u8, url_path: []const u8, stats: *http.Stats, is_head: bool, client_ip: []const u8) !void {
    var entries_buf: [512]fsutil.DirEntry = undefined;
    const entries = fsutil.listDir(disk_path, &entries_buf) catch {
        try sendStatus(client, 500, "listing error");
        stats.recordStatus(500);
        recordLog(client_ip, if (is_head) "HEAD" else "GET", url_path, 500, 0);
        return;
    };

    std.sort.pdq(fsutil.DirEntry, entries, {}, struct {
        fn lessThan(_: void, a: fsutil.DirEntry, b: fsutil.DirEntry) bool {
            if (a.is_dir != b.is_dir) {
                return a.is_dir;
            }
            return std.mem.lessThan(u8, a.nameSlice(), b.nameSlice());
        }
    }.lessThan);

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);

    try body.appendSlice(allocator, "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
    try body.print(allocator, "<title>Index of {s}</title>", .{url_path});
    try body.appendSlice(allocator, "<style>" ++
        ":root{--bg:#0f111a;--card:#181b28;--text:#e1e4ed;--sub:#8b92a5;--border:#262a3d;--accent:#6fe89e;--link:#78b4f0}" ++
        "@media(prefers-color-scheme:light){:root{--bg:#f8f9fc;--card:#ffffff;--text:#1e222e;--sub:#636b7e;--border:#e2e5f0;--accent:#10b981;--link:#2563eb}}" ++
        "body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--text);margin:0;padding:2rem}" ++
        ".container{max-width:960px;margin:0 auto;background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1.5rem;box-shadow:0 4px 12px rgba(0,0,0,0.05)}" ++
        "h1{margin:0 0 1rem;font-size:1.4rem;font-weight:600;display:flex;align-items:center;gap:0.5rem;word-break:break-all}" ++
        ".crumb{color:var(--sub);text-decoration:none}.crumb:hover{color:var(--accent)}" ++
        "table{width:100%;border-collapse:collapse;margin-top:1rem;font-size:0.92rem}" ++
        "th,td{text-align:left;padding:0.6rem 0.8rem;border-bottom:1px solid var(--border)}" ++
        "th{color:var(--sub);font-weight:500;font-size:0.8rem;text-transform:uppercase;letter-spacing:0.05em}" ++
        "tr:hover td{background:rgba(255,255,255,0.02)}" ++
        "a{color:var(--link);text-decoration:none;font-weight:500}a:hover{text-decoration:underline}" ++
        ".icon{display:inline-block;width:1.2rem;text-align:center;margin-right:0.4rem;color:var(--sub)}" ++
        ".size,.mtime{color:var(--sub);font-family:monospace;font-size:0.85rem}" ++
        ".footer{margin-top:1.5rem;font-size:0.8rem;color:var(--sub);text-align:right}" ++
        "</style></head><body><div class=\"container\">");

    try body.print(allocator, "<h1>Index of {s}</h1>", .{url_path});

    try body.appendSlice(allocator, "<table><thead><tr><th>Name</th><th style=\"width:120px\">Size</th><th style=\"width:180px\">Modified</th></tr></thead><tbody>");

    if (!std.mem.eql(u8, url_path, "/")) {
        try body.appendSlice(allocator, "<tr><td><span class=\"icon\">📁</span><a href=\"../\">../</a></td><td class=\"size\">-</td><td class=\"mtime\">-</td></tr>");
    }

    var size_buf: [32]u8 = undefined;
    for (entries) |e| {
        const icon: []const u8 = if (e.is_dir) "📁" else "📄";
        const suffix: []const u8 = if (e.is_dir) "/" else "";
        const formatted_size = if (e.is_dir) "-" else fsutil.formatSize(&size_buf, e.size);

        try body.print(allocator, "<tr><td><span class=\"icon\">{s}</span><a href=\"{s}{s}\">{s}{s}</a></td><td class=\"size\">{s}</td><td class=\"mtime\">{d}</td></tr>", .{
            icon,
            e.nameSlice(),
            suffix,
            e.nameSlice(),
            suffix,
            formatted_size,
            e.mtime_sec,
        });
    }

    try body.appendSlice(allocator, "</tbody></table><div class=\"footer\">Powered by ⚡ <b>zserve</b></div></div></body></html>");

    var header_buf: [256]u8 = undefined;
    const header = try std.fmt.bufPrint(&header_buf, "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{body.items.len});

    _ = linux.write(client, header.ptr, header.len);
    if (!is_head) {
        _ = linux.write(client, body.items.ptr, body.items.len);
    }

    const sent_bytes = if (is_head) 0 else body.items.len;
    stats.bytes_served += sent_bytes;
    stats.recordStatus(200);
    recordLog(client_ip, if (is_head) "HEAD" else "GET", url_path, 200, sent_bytes);
}

fn sendStatus(client: i32, status: u16, message: []const u8) !void {
    var buf: [256]u8 = undefined;
    const text = http.statusText(status);
    const header = try std.fmt.bufPrint(&buf, "HTTP/1.1 {d} {s}\r\nContent-Type: text/plain\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ status, text, message.len, message });
    _ = linux.write(client, header.ptr, header.len);
}

fn sendRedirect(client: i32, status: u16, location: []const u8) !void {
    var buf: [512]u8 = undefined;
    const text = http.statusText(status);
    const header = try std.fmt.bufPrint(&buf, "HTTP/1.1 {d} {s}\r\nLocation: {s}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", .{ status, text, location });
    _ = linux.write(client, header.ptr, header.len);
}

fn renderDashboard(stats: *const http.Stats, root: []const u8, port: u16) void {
    std.debug.print("\x1b[2J\x1b[H", .{});
    std.debug.print("{s}{s}zserve{s}  serving {s}{s}{s} on :{d}  ctrl+c to quit\n\n", .{ COL_BOLD, COL_ACCENT, COL_RESET, COL_SUBTLE, root, COL_RESET, port });

    var bytes_buf: [32]u8 = undefined;
    const formatted_bytes = fsutil.formatSize(&bytes_buf, stats.bytes_served);

    std.debug.print("requests  {s}{d:>8}{s}     bytes  {s}{s:>10}{s}\n\n", .{
        COL_ACCENT, stats.requests_total, COL_RESET,
        COL_ACCENT, formatted_bytes, COL_RESET,
    });

    std.debug.print("{s}2xx{s} {d:>6}    {s}3xx{s} {d:>6}    {s}4xx{s} {d:>6}    {s}5xx{s} {d:>6}\n\n", .{
        COL_2XX, COL_RESET, stats.status_2xx,
        COL_3XX, COL_RESET, stats.status_3xx,
        COL_4XX, COL_RESET, stats.status_4xx,
        COL_5XX, COL_RESET, stats.status_5xx,
    });

    std.debug.print("{s}recent requests{s}\n", .{ COL_SUBTLE, COL_RESET });
    if (log_ring.count == 0) {
        std.debug.print("  {s}(no requests logged yet){s}\n", .{ COL_SUBTLE, COL_RESET });
    } else {
        var idx: usize = 0;
        const start = if (log_ring.count == log_ring.entries.len) log_ring.head else 0;
        while (idx < log_ring.count) : (idx += 1) {
            const pos = (start + idx) % log_ring.entries.len;
            const item = log_ring.entries[pos];
            const col = switch (item.status / 100) {
                2 => COL_2XX,
                3 => COL_3XX,
                4 => COL_4XX,
                5 => COL_5XX,
                else => COL_RESET,
            };
            std.debug.print("  {s}{s:<15}{s}  {s:<5}  {s}{d:>3}{s}  {s}\n", .{
                COL_SUBTLE,
                item.client_ip[0..item.client_ip_len],
                COL_RESET,
                item.method[0..item.method_len],
                col,
                item.status,
                COL_RESET,
                item.path[0..item.path_len],
            });
        }
    }

    std.debug.print("\n{s}top paths{s}\n", .{ COL_SUBTLE, COL_RESET });
    var path_found = false;
    for (stats.top_paths) |p| {
        if (p.count == 0) continue;
        path_found = true;
        std.debug.print("  {s}{d:>6}{s}  {s}\n", .{ COL_SUBTLE, p.count, COL_RESET, p.path[0..p.len] });
    }
    if (!path_found) {
        std.debug.print("  {s}(no paths recorded){s}\n", .{ COL_SUBTLE, COL_RESET });
    }
}

test {
    std.testing.refAllDecls(@This());
}
