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
const COL_2XX = "\x1b[38;2;111;232;158m";
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

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var cmdline_buf: [1024]u8 = undefined;
    var args_storage: [8][]const u8 = undefined;
    const args = readCmdlineArgs(&cmdline_buf, &args_storage);

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
    _ = try checkErrno(linux.bind(sock, @ptrCast(&addr), @sizeOf(linux.sockaddr.in)));
    _ = try checkErrno(linux.listen(sock, 16));

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

        handleConnection(allocator, client, root, &req_buf, &stats) catch {};
        renderDashboard(&stats, root, port);
    }
}

fn handleConnection(allocator: std.mem.Allocator, client: i32, root: []const u8, req_buf: []u8, stats: *http.Stats) !void {
    const n_rc = linux.read(client, req_buf.ptr, req_buf.len);
    const n = try checkErrno(n_rc);
    if (n == 0) return;

    stats.requests_total += 1;

    const req = http.parseRequestLine(req_buf[0..n]) catch {
        try sendStatus(client, 400, "");
        stats.recordStatus(400);
        return;
    };

    stats.recordPath(req.path);

    var path_buf: [1024]u8 = undefined;
    const disk_path = http.safeJoin(&path_buf, root, req.path) orelse {
        try sendStatus(client, 403, "");
        stats.recordStatus(403);
        return;
    };

    var pathz_buf: [1024]u8 = undefined;
    const disk_pathz = std.fmt.bufPrintZ(&pathz_buf, "{s}", .{disk_path}) catch {
        try sendStatus(client, 500, "");
        stats.recordStatus(500);
        return;
    };

    const kind = fsutil.statKind(disk_pathz);
    switch (kind) {
        .missing => {
            try sendStatus(client, 404, "not found");
            stats.recordStatus(404);
        },
        .dir => {
            try serveDirListing(allocator, client, disk_pathz, req.path, stats);
        },
        .file => {
            try serveFile(allocator, client, disk_pathz, stats);
        },
        .other => {
            try sendStatus(client, 403, "");
            stats.recordStatus(403);
        },
    }
}

fn serveFile(allocator: std.mem.Allocator, client: i32, path: [:0]const u8, stats: *http.Stats) !void {
    const data = fsutil.readFile(allocator, path) catch {
        try sendStatus(client, 500, "read error");
        stats.recordStatus(500);
        return;
    };
    defer allocator.free(data);

    const ctype = http.contentType(path);
    var header_buf: [256]u8 = undefined;
    const header = try std.fmt.bufPrint(&header_buf, "HTTP/1.1 200 OK\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{ ctype, data.len });

    _ = linux.write(client, header.ptr, header.len);
    _ = linux.write(client, data.ptr, data.len);
    stats.bytes_served += data.len;
    stats.recordStatus(200);
}

fn serveDirListing(allocator: std.mem.Allocator, client: i32, disk_path: [:0]const u8, url_path: []const u8, stats: *http.Stats) !void {
    var entries_buf: [512]fsutil.DirEntry = undefined;
    const entries = fsutil.listDir(disk_path, &entries_buf) catch {
        try sendStatus(client, 500, "listing error");
        stats.recordStatus(500);
        return;
    };

    std.sort.pdq(fsutil.DirEntry, entries, {}, struct {
        fn lessThan(_: void, a: fsutil.DirEntry, b: fsutil.DirEntry) bool {
            return std.mem.lessThan(u8, a.nameSlice(), b.nameSlice());
        }
    }.lessThan);

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);

    try body.print(allocator, "<!doctype html><html><head><meta charset=\"utf-8\"><title>{s}</title></head><body><h1>{s}</h1><ul>", .{ url_path, url_path });
    if (!std.mem.eql(u8, url_path, "/")) {
        try body.appendSlice(allocator, "<li><a href=\"../\">../</a></li>");
    }
    for (entries) |e| {
        const suffix: []const u8 = if (e.is_dir) "/" else "";
        try body.print(allocator, "<li><a href=\"{s}{s}\">{s}{s}</a></li>", .{ e.nameSlice(), suffix, e.nameSlice(), suffix });
    }
    try body.appendSlice(allocator, "</ul></body></html>");

    var header_buf: [256]u8 = undefined;
    const header = try std.fmt.bufPrint(&header_buf, "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{body.items.len});

    _ = linux.write(client, header.ptr, header.len);
    _ = linux.write(client, body.items.ptr, body.items.len);
    stats.bytes_served += body.items.len;
    stats.recordStatus(200);
}

fn sendStatus(client: i32, status: u16, message: []const u8) !void {
    var buf: [256]u8 = undefined;
    const text = http.statusText(status);
    const header = try std.fmt.bufPrint(&buf, "HTTP/1.1 {d} {s}\r\nContent-Type: text/plain\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ status, text, message.len, message });
    _ = linux.write(client, header.ptr, header.len);
}

fn renderDashboard(stats: *const http.Stats, root: []const u8, port: u16) void {
    std.debug.print("\x1b[2J\x1b[H", .{});
    std.debug.print("{s}zserve{s} {s}{s} on :{d}{s}  ctrl+c to quit\n\n", .{ COL_ACCENT, COL_RESET, COL_SUBTLE, root, port, COL_RESET });

    std.debug.print("requests  {s}{d}{s}\n", .{ COL_ACCENT, stats.requests_total, COL_RESET });
    std.debug.print("bytes     {s}{d}{s}\n\n", .{ COL_ACCENT, stats.bytes_served, COL_RESET });

    std.debug.print("{s}2xx{s} {d}   {s}4xx{s} {d}   {s}5xx{s} {d}\n\n", .{
        COL_2XX, COL_RESET, stats.status_2xx,
        COL_4XX, COL_RESET, stats.status_4xx,
        COL_5XX, COL_RESET, stats.status_5xx,
    });

    std.debug.print("{s}top paths{s}\n", .{ COL_SUBTLE, COL_RESET });
    for (stats.top_paths) |p| {
        if (p.count == 0) continue;
        std.debug.print("  {s}{d:>4}{s}  {s}\n", .{ COL_SUBTLE, p.count, COL_RESET, p.path[0..p.len] });
    }
}

test {
    std.testing.refAllDecls(@This());
}

