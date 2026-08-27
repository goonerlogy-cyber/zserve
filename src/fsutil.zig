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

pub const DirEntry = struct {
    name: [256]u8,
    name_len: usize,
    is_dir: bool,

    pub fn nameSlice(self: *const DirEntry) []const u8 {
        return self.name[0..self.name_len];
    }
};

pub fn listDir(path: [:0]const u8, out: []DirEntry) ![]DirEntry {
    const fd_rc = linux.open(path.ptr, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
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
}
