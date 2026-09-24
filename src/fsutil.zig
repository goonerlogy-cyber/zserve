const std = @import("std");
const linux = std.os.linux;

pub const FileError = error{
    NotFound,
    NotAFile,
    Other,
};

fn checkErrno(rc: usize) !usize {
    const signed: isize = @bitCast(rc);
    if (signed < 0) {
        const errno: linux.E = @enumFromInt(-signed);
        return switch (errno) {
            .NOENT => FileError.NotFound,
            .ISDIR, .NOTDIR => FileError.NotAFile,
            else => FileError.Other,
        };
    }
    return rc;
}

pub const Kind = enum { file, dir, other, missing };

pub fn statKind(path: [:0]const u8) Kind {
    var stx: linux.Statx = undefined;
    const rc = linux.statx(linux.AT.FDCWD, path.ptr, 0, .{ .TYPE = true, .SIZE = true }, &stx);
    if (@as(isize, @bitCast(rc)) < 0) return .missing;
    const mode = stx.mode;
    if ((mode & linux.S.IFMT) == linux.S.IFDIR) return .dir;
    if ((mode & linux.S.IFMT) == linux.S.IFREG) return .file;
    return .other;
}

pub fn fileSize(path: [:0]const u8) !u64 {
    var stx: linux.Statx = undefined;
    const rc = linux.statx(linux.AT.FDCWD, path.ptr, 0, .{ .SIZE = true }, &stx);
    _ = try checkErrno(rc);
    return stx.size;
}

pub fn readFile(allocator: std.mem.Allocator, path: [:0]const u8) ![]u8 {
    const fd_rc = linux.open(path.ptr, .{ .ACCMODE = .RDONLY }, 0);
    const fd: i32 = @intCast(try checkErrno(fd_rc));
    defer _ = linux.close(fd);

    const size = try fileSize(path);
    const buf = try allocator.alloc(u8, size);
    errdefer allocator.free(buf);

    var total: usize = 0;
    while (total < buf.len) {
        const n = try checkErrno(linux.read(fd, buf.ptr + total, buf.len - total));
        if (n == 0) break;
        total += n;
    }
    return buf[0..total];
}

pub fn sendfileStream(client_fd: i32, path: [:0]const u8, start_offset: u64, length: u64) !u64 {
    const fd_rc = linux.open(path.ptr, .{ .ACCMODE = .RDONLY }, 0);
    const fd: i32 = @intCast(try checkErrno(fd_rc));
    defer _ = linux.close(fd);

    var offset: usize = @intCast(start_offset);
    var remaining: usize = @intCast(length);
    var total_sent: u64 = 0;

    while (remaining > 0) {
        const to_send = @min(remaining, 1024 * 1024);
        const rc = linux.sendfile(client_fd, fd, &offset, to_send);
        const signed: isize = @bitCast(rc);
        if (signed < 0) {
            var chunk_buf: [16384]u8 = undefined;
            _ = checkErrno(linux.lseek(fd, @intCast(offset), linux.SEEK.SET)) catch return error.Other;
            while (remaining > 0) {
                const chunk_size = @min(remaining, chunk_buf.len);
                const read_n = try checkErrno(linux.read(fd, &chunk_buf, chunk_size));
                if (read_n == 0) break;
                var written: usize = 0;
                while (written < read_n) {
                    const write_n = try checkErrno(linux.write(client_fd, chunk_buf[written..read_n].ptr, read_n - written));
                    if (write_n == 0) break;
                    written += write_n;
                }
                total_sent += written;
                remaining -= written;
            }
            return total_sent;
        }
        if (rc == 0) break;
        total_sent += rc;
        remaining -= rc;
    }
    return total_sent;
}

pub const DirEntry = struct {
    name: [256]u8 = std.mem.zeroes([256]u8),
    name_len: usize = 0,
    is_dir: bool = false,
    size: u64 = 0,
    mtime_sec: i64 = 0,

    pub fn nameSlice(self: *const DirEntry) []const u8 {
        return self.name[0..self.name_len];
    }
};

pub fn formatSize(buf: []u8, bytes: u64) []const u8 {
    if (bytes < 1024) {
        return std.fmt.bufPrint(buf, "{d} B", .{bytes}) catch "";
    }
    const units = [_][]const u8{ "KB", "MB", "GB", "TB" };
    var val: f64 = @floatFromInt(bytes);
    var unit_idx: usize = 0;
    while (val >= 1024.0 and unit_idx < units.len - 1) {
        val /= 1024.0;
        unit_idx += 1;
    }
    if (unit_idx == 0) {
        val /= 1024.0;
    }
    if (val >= 100.0) {
        return std.fmt.bufPrint(buf, "{d:.0} {s}", .{ val, units[unit_idx] }) catch "";
    } else if (val >= 10.0) {
        return std.fmt.bufPrint(buf, "{d:.1} {s}", .{ val, units[unit_idx] }) catch "";
    } else {
        return std.fmt.bufPrint(buf, "{d:.2} {s}", .{ val, units[unit_idx] }) catch "";
    }
}

pub fn listDir(dir_path: [:0]const u8, out: []DirEntry) ![]DirEntry {
    const fd_rc = linux.open(dir_path.ptr, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
    const fd: i32 = @intCast(try checkErrno(fd_rc));
    defer _ = linux.close(fd);

    var count: usize = 0;
    var buf: [8192]u8 = undefined;

    while (count < out.len) {
        const n = try checkErrno(linux.getdents64(fd, &buf, buf.len));
        if (n == 0) break;

        var offset: usize = 0;
        while (offset < n and count < out.len) {
            const d: *align(1) const linux.dirent64 = @ptrCast(&buf[offset]);
            const name_offset = 19;
            const name_ptr: [*:0]const u8 = @ptrCast(&buf[offset + name_offset]);
            const name = std.mem.span(name_ptr);

            if (!std.mem.eql(u8, name, ".") and !std.mem.eql(u8, name, "..")) {
                const len = @min(name.len, out[count].name.len);
                @memcpy(out[count].name[0..len], name[0..len]);
                out[count].name_len = len;
                out[count].is_dir = (d.type == linux.DT.DIR);

                var stx: linux.Statx = undefined;
                var child_path_buf: [1024]u8 = undefined;
                if (std.fmt.bufPrintZ(&child_path_buf, "{s}/{s}", .{ dir_path, name })) |child_pathz| {
                    const stx_rc = linux.statx(linux.AT.FDCWD, child_pathz.ptr, 0, .{ .TYPE = true, .SIZE = true, .MTIME = true }, &stx);
                    if (@as(isize, @bitCast(stx_rc)) >= 0) {
                        out[count].size = stx.size;
                        out[count].mtime_sec = stx.mtime.sec;
                        if ((stx.mode & linux.S.IFMT) == linux.S.IFDIR) {
                            out[count].is_dir = true;
                        }
                    } else {
                        out[count].size = 0;
                        out[count].mtime_sec = 0;
                    }
                } else |_| {
                    out[count].size = 0;
                    out[count].mtime_sec = 0;
                }

                count += 1;
            }

            offset += d.reclen;
        }
    }

    return out[0..count];
}

test "statKind identifies files dirs and missing paths" {
    const tmp_dir = "/tmp";
    try std.testing.expectEqual(Kind.dir, statKind(tmp_dir));

    var path_buf: [256]u8 = undefined;
    const missing = try std.fmt.bufPrintZ(&path_buf, "/tmp/zserve-fsutil-test-does-not-exist-xyz", .{});
    try std.testing.expectEqual(Kind.missing, statKind(missing));
}

test "readFile and listDir round trip against a real temp directory" {
    const allocator = std.testing.allocator;

    var buf: [64]u8 = undefined;
    const dir_path = try std.fmt.bufPrintZ(&buf, "/tmp/zserve-fsutil-test-dir", .{});

    _ = linux.rmdir(dir_path.ptr);
    _ = linux.mkdir(dir_path.ptr, 0o755);
    defer _ = linux.rmdir(dir_path.ptr);

    var file_buf: [64]u8 = undefined;
    const file_path = try std.fmt.bufPrintZ(&file_buf, "{s}/hello.txt", .{dir_path});
    const fd: i32 = @intCast(try checkErrno(linux.open(file_path.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644)));
    _ = linux.write(fd, "hi there", 8);
    _ = linux.close(fd);
    defer _ = linux.unlink(file_path.ptr);

    try std.testing.expectEqual(Kind.file, statKind(file_path));
    const data = try readFile(allocator, file_path);
    defer allocator.free(data);
    try std.testing.expectEqualStrings("hi there", data);

    var entries_buf: [16]DirEntry = undefined;
    const entries = try listDir(dir_path, &entries_buf);
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqualStrings("hello.txt", entries[0].nameSlice());
    try std.testing.expect(!entries[0].is_dir);
    try std.testing.expectEqual(@as(u64, 8), entries[0].size);
}

test "formatSize formats byte units correctly" {
    var b: [32]u8 = undefined;
    try std.testing.expectEqualStrings("500 B", formatSize(&b, 500));
    try std.testing.expectEqualStrings("1.50 KB", formatSize(&b, 1536));
    try std.testing.expectEqualStrings("10.0 KB", formatSize(&b, 10240));
    try std.testing.expectEqualStrings("2.50 MB", formatSize(&b, 2621440));
}
