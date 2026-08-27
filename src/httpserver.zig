const std = @import("std");
const linux = std.os.linux;

fn checkErrno(rc: usize) !usize {
    const signed: isize = @bitCast(rc);
    if (signed < 0) return error.SyscallFailed;
    return rc;
}

pub const Stats = struct {
    requests_total: u64 = 0,
    bytes_served: u64 = 0,
    status_2xx: u64 = 0,
    status_3xx: u64 = 0,
    status_4xx: u64 = 0,
    status_5xx: u64 = 0,
    top_paths: [8]PathCount = std.mem.zeroes([8]PathCount),

    pub const PathCount = struct {
        path: [64]u8 = std.mem.zeroes([64]u8),
        len: usize = 0,
        count: u64 = 0,
    };

    pub fn recordStatus(self: *Stats, status: u16) void {
        switch (status / 100) {
            2 => self.status_2xx += 1,
            3 => self.status_3xx += 1,
            4 => self.status_4xx += 1,
            5 => self.status_5xx += 1,
            else => {},
        }
    }

    pub fn recordPath(self: *Stats, path: []const u8) void {
        for (&self.top_paths) |*entry| {
            if (entry.len == path.len and std.mem.eql(u8, entry.path[0..entry.len], path)) {
                entry.count += 1;
                return;
            }
        }
        for (&self.top_paths) |*entry| {
            if (entry.count == 0) {
                const len = @min(path.len, entry.path.len);
                @memcpy(entry.path[0..len], path[0..len]);
                entry.len = len;
                entry.count = 1;
                return;
            }
        }
        var min_idx: usize = 0;
        for (self.top_paths, 0..) |entry, i| {
            if (entry.count < self.top_paths[min_idx].count) min_idx = i;
        }
        if (self.top_paths[min_idx].count < 2) {
            const len = @min(path.len, self.top_paths[min_idx].path.len);
            @memcpy(self.top_paths[min_idx].path[0..len], path[0..len]);
            self.top_paths[min_idx].len = len;
            self.top_paths[min_idx].count = 1;
        }
    }
};

pub const Request = struct {
    method: []const u8,
    path: []const u8,
};

pub const ParseError = error{
    BadRequest,
};

pub fn parseRequestLine(buf: []const u8) ParseError!Request {
    const line_end = std.mem.indexOf(u8, buf, "\r\n") orelse return ParseError.BadRequest;
    const line = buf[0..line_end];

    var parts = std.mem.splitScalar(u8, line, ' ');
    const method = parts.next() orelse return ParseError.BadRequest;
    const raw_path = parts.next() orelse return ParseError.BadRequest;
    _ = parts.next() orelse return ParseError.BadRequest;

    const q = std.mem.indexOfScalar(u8, raw_path, '?');
    const path = if (q) |i| raw_path[0..i] else raw_path;

    return .{ .method = method, .path = path };
}

pub fn safeJoin(buf: []u8, root: []const u8, url_path: []const u8) ?[]const u8 {
    var decoded_buf: [1024]u8 = undefined;
    const decoded = urlDecode(&decoded_buf, url_path) orelse return null;
    if (std.mem.indexOf(u8, decoded, "..") != null) return null;

    const trimmed = std.mem.trim(u8, decoded, "/");
    if (trimmed.len == 0) {
        return std.fmt.bufPrint(buf, "{s}/", .{root}) catch null;
    }
    return std.fmt.bufPrint(buf, "{s}/{s}", .{ root, trimmed }) catch null;
}

fn urlDecode(out: []u8, in: []const u8) ?[]const u8 {
    var i: usize = 0;
    var o: usize = 0;
    while (i < in.len) {
        if (o >= out.len) return null;
        if (in[i] == '%' and i + 2 < in.len) {
            const hi = std.fmt.charToDigit(in[i + 1], 16) catch return null;
            const lo = std.fmt.charToDigit(in[i + 2], 16) catch return null;
            out[o] = @as(u8, hi) * 16 + lo;
            o += 1;
            i += 3;
        } else {
            out[o] = in[i];
            o += 1;
            i += 1;
        }
    }
    return out[0..o];
}

pub fn contentType(path: []const u8) []const u8 {
    const ext = std.fs.path.extension(path);
    if (std.mem.eql(u8, ext, ".html") or std.mem.eql(u8, ext, ".htm")) return "text/html; charset=utf-8";
    if (std.mem.eql(u8, ext, ".css")) return "text/css";
    if (std.mem.eql(u8, ext, ".js")) return "application/javascript";
    if (std.mem.eql(u8, ext, ".json")) return "application/json";
    if (std.mem.eql(u8, ext, ".png")) return "image/png";
    if (std.mem.eql(u8, ext, ".jpg") or std.mem.eql(u8, ext, ".jpeg")) return "image/jpeg";
    if (std.mem.eql(u8, ext, ".svg")) return "image/svg+xml";
    if (std.mem.eql(u8, ext, ".txt")) return "text/plain; charset=utf-8";
    return "application/octet-stream";
}

pub fn statusText(status: u16) []const u8 {
    return switch (status) {
        200 => "OK",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        else => "Unknown",
    };
}

test "parseRequestLine extracts method and path" {
    const req = try parseRequestLine("GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n");
    try std.testing.expectEqualStrings("GET", req.method);
    try std.testing.expectEqualStrings("/index.html", req.path);
}

test "parseRequestLine strips query string" {
    const req = try parseRequestLine("GET /search?q=hi HTTP/1.1\r\n\r\n");
    try std.testing.expectEqualStrings("/search", req.path);
}

test "parseRequestLine rejects malformed request" {
    try std.testing.expectError(ParseError.BadRequest, parseRequestLine("garbage"));
}

test "safeJoin rejects any path containing dotdot" {
    var buf: [256]u8 = undefined;
    try std.testing.expect(safeJoin(&buf, "/srv/www", "/../etc/passwd") == null);
    try std.testing.expect(safeJoin(&buf, "/srv/www", "/a/../../etc") == null);
}

test "safeJoin joins a normal path under root" {
    var buf: [256]u8 = undefined;
    const result = safeJoin(&buf, "/srv/www", "/sub/file.txt").?;
    try std.testing.expectEqualStrings("/srv/www/sub/file.txt", result);
}

test "safeJoin of root path returns the root with trailing slash" {
    var buf: [256]u8 = undefined;
    const result = safeJoin(&buf, "/srv/www", "/").?;
    try std.testing.expectEqualStrings("/srv/www/", result);
}

test "safeJoin url-decodes percent escapes before joining" {
    var buf: [256]u8 = undefined;
    const result = safeJoin(&buf, "/srv/www", "/my%20file.txt").?;
    try std.testing.expectEqualStrings("/srv/www/my file.txt", result);
}

test "safeJoin rejects dotdot hidden behind percent-encoded dots" {
    var buf: [256]u8 = undefined;
    const result = safeJoin(&buf, "/srv/www", "/%2e%2e/%2e%2e/etc/passwd");
    try std.testing.expect(result == null);
}

test "contentType maps known extensions" {
    try std.testing.expectEqualStrings("text/html; charset=utf-8", contentType("index.html"));
    try std.testing.expectEqualStrings("text/css", contentType("style.css"));
    try std.testing.expectEqualStrings("application/octet-stream", contentType("data.bin"));
}

test "Stats.recordPath tracks up to 8 distinct paths with counts" {
    var stats = Stats{};
    stats.recordPath("/a");
    stats.recordPath("/a");
    stats.recordPath("/b");
    try std.testing.expectEqual(@as(u64, 2), stats.top_paths[0].count);
    try std.testing.expectEqual(@as(u64, 1), stats.top_paths[1].count);
}

test "Stats.recordStatus buckets by hundreds digit" {
    var stats = Stats{};
    stats.recordStatus(200);
    stats.recordStatus(404);
    stats.recordStatus(500);
    try std.testing.expectEqual(@as(u64, 1), stats.status_2xx);
    try std.testing.expectEqual(@as(u64, 1), stats.status_4xx);
    try std.testing.expectEqual(@as(u64, 1), stats.status_5xx);
}
