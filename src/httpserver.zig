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
    range_header: ?[]const u8 = null,
};

pub const RangeSpec = struct {
    start: u64,
    end: ?u64,
};

pub const ParseError = error{
    BadRequest,
    MethodNotAllowed,
};

pub fn parseRequestLine(buf: []const u8) ParseError!Request {
    const line_end = std.mem.indexOf(u8, buf, "\r\n") orelse return ParseError.BadRequest;
    const line = buf[0..line_end];

    var parts = std.mem.splitScalar(u8, line, ' ');
    const method = parts.next() orelse return ParseError.BadRequest;
    const raw_path = parts.next() orelse return ParseError.BadRequest;
    _ = parts.next() orelse return ParseError.BadRequest;

    if (!std.mem.eql(u8, method, "GET") and !std.mem.eql(u8, method, "HEAD")) {
        return ParseError.MethodNotAllowed;
    }

    var clean_path = raw_path;
    if (std.mem.indexOfScalar(u8, clean_path, '#')) |i| {
        clean_path = clean_path[0..i];
    }
    if (std.mem.indexOfScalar(u8, clean_path, '?')) |i| {
        clean_path = clean_path[0..i];
    }

    var range_val: ?[]const u8 = null;
    var headers_it = std.mem.splitSequence(u8, buf[line_end + 2 ..], "\r\n");
    while (headers_it.next()) |h| {
        if (h.len == 0) break;
        if (std.mem.indexOfScalar(u8, h, ':')) |colon| {
            const name = std.mem.trim(u8, h[0..colon], " \t");
            if (std.ascii.eqlIgnoreCase(name, "range")) {
                range_val = std.mem.trim(u8, h[colon + 1 ..], " \t");
            }
        }
    }

    return .{ .method = method, .path = clean_path, .range_header = range_val };
}

pub fn parseRangeHeader(range_str: []const u8, file_size: u64) ?RangeSpec {
    if (!std.mem.startsWith(u8, range_str, "bytes=")) return null;
    const spec = range_str["bytes=".len..];
    const dash = std.mem.indexOfScalar(u8, spec, '-') orelse return null;
    const start_str = spec[0..dash];
    const end_str = spec[dash + 1 ..];

    if (start_str.len == 0) {
        const suffix_len = std.fmt.parseInt(u64, end_str, 10) catch return null;
        if (suffix_len == 0 or suffix_len > file_size) return RangeSpec{ .start = 0, .end = if (file_size > 0) file_size - 1 else 0 };
        return RangeSpec{ .start = file_size - suffix_len, .end = file_size - 1 };
    }

    const start = std.fmt.parseInt(u64, start_str, 10) catch return null;
    if (start >= file_size) return null;

    if (end_str.len == 0) {
        return RangeSpec{ .start = start, .end = file_size - 1 };
    }

    const end = std.fmt.parseInt(u64, end_str, 10) catch return null;
    if (end < start) return null;
    const clamped_end = @min(end, file_size - 1);
    return RangeSpec{ .start = start, .end = clamped_end };
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
            const val: u8 = @as(u8, hi) * 16 + lo;
            if (val == 0) return null;
            out[o] = val;
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
    if (std.mem.eql(u8, ext, ".css")) return "text/css; charset=utf-8";
    if (std.mem.eql(u8, ext, ".js") or std.mem.eql(u8, ext, ".mjs")) return "text/javascript; charset=utf-8";
    if (std.mem.eql(u8, ext, ".json")) return "application/json; charset=utf-8";
    if (std.mem.eql(u8, ext, ".png")) return "image/png";
    if (std.mem.eql(u8, ext, ".jpg") or std.mem.eql(u8, ext, ".jpeg")) return "image/jpeg";
    if (std.mem.eql(u8, ext, ".gif")) return "image/gif";
    if (std.mem.eql(u8, ext, ".webp")) return "image/webp";
    if (std.mem.eql(u8, ext, ".avif")) return "image/avif";
    if (std.mem.eql(u8, ext, ".svg")) return "image/svg+xml";
    if (std.mem.eql(u8, ext, ".ico")) return "image/x-icon";
    if (std.mem.eql(u8, ext, ".mp4")) return "video/mp4";
    if (std.mem.eql(u8, ext, ".webm")) return "video/webm";
    if (std.mem.eql(u8, ext, ".mp3")) return "audio/mpeg";
    if (std.mem.eql(u8, ext, ".wav")) return "audio/wav";
    if (std.mem.eql(u8, ext, ".ogg")) return "audio/ogg";
    if (std.mem.eql(u8, ext, ".pdf")) return "application/pdf";
    if (std.mem.eql(u8, ext, ".woff2")) return "font/woff2";
    if (std.mem.eql(u8, ext, ".woff")) return "font/woff";
    if (std.mem.eql(u8, ext, ".ttf")) return "font/ttf";
    if (std.mem.eql(u8, ext, ".txt") or std.mem.eql(u8, ext, ".md") or std.mem.eql(u8, ext, ".log")) return "text/plain; charset=utf-8";
    if (std.mem.eql(u8, ext, ".wasm")) return "application/wasm";
    if (std.mem.eql(u8, ext, ".xml")) return "application/xml; charset=utf-8";
    return "application/octet-stream";
}

pub fn statusText(status: u16) []const u8 {
    return switch (status) {
        200 => "OK",
        206 => "Partial Content",
        301 => "Moved Permanently",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        416 => "Range Not Satisfiable",
        500 => "Internal Server Error",
        else => "Unknown",
    };
}

test "parseRequestLine extracts method and path" {
    const req = try parseRequestLine("GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n");
    try std.testing.expectEqualStrings("GET", req.method);
    try std.testing.expectEqualStrings("/index.html", req.path);
}

test "parseRequestLine handles HEAD method" {
    const req = try parseRequestLine("HEAD /video.mp4 HTTP/1.1\r\n\r\n");
    try std.testing.expectEqualStrings("HEAD", req.method);
    try std.testing.expectEqualStrings("/video.mp4", req.path);
}

test "parseRequestLine rejects POST or PUT" {
    try std.testing.expectError(ParseError.MethodNotAllowed, parseRequestLine("POST /data HTTP/1.1\r\n\r\n"));
}

test "parseRequestLine parses Range header" {
    const req = try parseRequestLine("GET /file.bin HTTP/1.1\r\nRange: bytes=100-200\r\n\r\n");
    try std.testing.expectEqualStrings("bytes=100-200", req.range_header.?);
}

test "parseRangeHeader parses byte range correctly" {
    const range = parseRangeHeader("bytes=10-20", 100).?;
    try std.testing.expectEqual(@as(u64, 10), range.start);
    try std.testing.expectEqual(@as(u64, 20), range.end.?);
}

test "parseRangeHeader parses open ended range" {
    const range = parseRangeHeader("bytes=50-", 100).?;
    try std.testing.expectEqual(@as(u64, 50), range.start);
    try std.testing.expectEqual(@as(u64, 99), range.end.?);
}

test "parseRequestLine strips query string and fragment" {
    const req = try parseRequestLine("GET /search?q=hi#section HTTP/1.1\r\n\r\n");
    try std.testing.expectEqualStrings("/search", req.path);
}

test "safeJoin rejects null bytes in encoded URL" {
    var buf: [256]u8 = undefined;
    try std.testing.expect(safeJoin(&buf, "/srv/www", "/file%00.txt") == null);
}

test "contentType maps new extensions" {
    try std.testing.expectEqualStrings("video/mp4", contentType("movie.mp4"));
    try std.testing.expectEqualStrings("font/woff2", contentType("font.woff2"));
    try std.testing.expectEqualStrings("text/javascript; charset=utf-8", contentType("script.mjs"));
}
