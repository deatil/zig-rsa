const std = @import("std");
const testing = std.testing;

// dst = x ^ y
pub fn xorBytes(dst: []u8, x: []const u8, y: []const u8) !void {
    const num = @min(x.len, y.len);
    if (dst.len < num) {
        return error.DstTooShort;
    }

    const xx = x[0..num];
    const yy = y[0..num];

    for (0..num) |i| {
        dst[i] = xx[i] ^ yy[i];
    }
}

// constantTimeByteEq returns 1 when x == y.
pub fn constantTimeByteEq(x: u8, y: u8) isize {
    const xy: u32 = x ^ y;
    return (xy -% 1) >> 31;
}

// constantTimeEq returns 1 when x == y.
pub fn constantTimeEq(x: isize, y: isize) isize {
    const xy: u32 = isizeToUsize(u32, x ^ y, 256 * 4);
    const xy2: u64 = xy;
    return @intCast((xy2 -% 1) >> 63);
}

// constantTimeSelect returns x when v == 1, and y when v == 0.
// it is undefined when v is any other value
pub fn constantTimeSelect(v: isize, x: isize, y: isize) isize {
    return (~(v - 1) & x) | ((v - 1) & y);
}

// constantTimeCompare returns 1 when x and y have equal contents.
// The runtime of this function is proportional of the length of x and y.
// It is *NOT* dependent on their content.
pub fn constantTimeCompare(x: []const u8, y: []const u8) isize {
    if (x.len != y.len) {
        return 0;
    }

    var v: u8 = 0;
    for (0..x.len) |i| {
        v |= x[i] ^ y[i];
    }

    return constantTimeByteEq(v, 0);
}

// constantTimeCopy copies the contents of y into x, when v == 1.
// When v == 0, x is left unchanged. this function is undefined, when
// v takes any other value
pub fn constantTimeCopy(v: isize, x: []u8, y: []const u8) !void {
    if (x.len != y.len) {
        return error.ArraysHaveDifferentLengths;
    }

    const xmask: u8 = isizeToUsize(u8, v - 1, 256);
    const ymask: u8 = isizeToUsize(u8, ~(v - 1), 256);
    for (0..x.len) |i| {
        x[i] = x[i] & xmask | y[i] & ymask;
    }
}

// constantTimeLessOrEq returns 1 if x <= y, and 0 otherwise.
// it is undefined when x or y are negative, or > (2^32 - 1)
pub fn constantTimeLessOrEq(x: isize, y: isize) isize {
    return ((x - y - 1) >> 31) & 1;
}

pub fn isizeToUsize(comptime T: type, x: isize, n: isize) T {
    return @intCast(@mod((@mod((x), n) + n), n));
}

test "constantTimeByteEq" {
    try testing.expectEqual(1, constantTimeByteEq(0, 0));
    try testing.expectEqual(1, constantTimeByteEq(1, 1));
    try testing.expectEqual(1, constantTimeByteEq(255, 255));
    try testing.expectEqual(0, constantTimeByteEq(255, 1));
    try testing.expectEqual(0, constantTimeByteEq(1, 255));
    try testing.expectEqual(0, constantTimeByteEq(2, 1));
}

test "constantTimeEq" {
    try testing.expectEqual(1, constantTimeEq(0, 0));
    try testing.expectEqual(1, constantTimeEq(255, 255));
    try testing.expectEqual(1, constantTimeEq(65536, 65536));
    try testing.expectEqual(1, constantTimeEq(-1, -1));
    try testing.expectEqual(1, constantTimeEq(-256, -256));
    try testing.expectEqual(0, constantTimeEq(-256, 256));
    try testing.expectEqual(0, constantTimeEq(0, 1));
    try testing.expectEqual(0, constantTimeEq(7, -1));
}

test "constantTimeSelect" {
    try testing.expectEqual(1, constantTimeSelect(1, 1, 0));
    try testing.expectEqual(1, constantTimeSelect(1, 1, 255));
    try testing.expectEqual(1, constantTimeSelect(1, 1, 255 * 255));
    try testing.expectEqual(2, constantTimeSelect(1, 2, 0));
    try testing.expectEqual(2, constantTimeSelect(1, 2, 255));
    try testing.expectEqual(2, constantTimeSelect(1, 2, 255 * 255));

    try testing.expectEqual(0, constantTimeSelect(0, 1, 0));
    try testing.expectEqual(255, constantTimeSelect(0, 1, 255));
    try testing.expectEqual(255 * 255, constantTimeSelect(0, 1, 255 * 255));
    try testing.expectEqual(0, constantTimeSelect(0, 2, 0));
    try testing.expectEqual(255, constantTimeSelect(0, 2, 255));
    try testing.expectEqual(255 * 255, constantTimeSelect(0, 2, 255 * 255));
}

test "constantTimeCompare" {
    try testing.expectEqual(1, constantTimeCompare(&.{ 1, 2, 3 }, &.{ 1, 2, 3 }));
    try testing.expectEqual(0, constantTimeCompare(&.{ 1, 2, 3 }, &.{ 1, 2, 9 }));
    try testing.expectEqual(0, constantTimeCompare(&.{ 1, 2, 3 }, &.{ 1, 2, 3, 4 }));
    try testing.expectEqual(0, constantTimeCompare(&.{ 1, 2, 3 }, &.{ 1, 2 }));
}

test "constantTimeCopy" {
    const y = [_]u8{ 3, 4, 5 };
    var x: [3]u8 = [_]u8{0} ** 3;
    try constantTimeCopy(0, x[0..], y[0..]);
    try testing.expectEqual([_]u8{0} ** 3, x);

    try constantTimeCopy(1, x[0..], y[0..]);
    try testing.expectEqual(y, x);
    try testing.expectEqual([_]u8{ 3, 4, 5 }, x);
}

test "constantTimeLessOrEq" {
    try testing.expectEqual(1, constantTimeLessOrEq(1, 1));
    try testing.expectEqual(1, constantTimeLessOrEq(1, 2));
    try testing.expectEqual(1, constantTimeLessOrEq(1, 3));
    try testing.expectEqual(1, constantTimeLessOrEq(255, 255));
    try testing.expectEqual(1, constantTimeLessOrEq(255, 256));
    try testing.expectEqual(1, constantTimeLessOrEq(255, 257));
    try testing.expectEqual(0, constantTimeLessOrEq(1, 0));
    try testing.expectEqual(0, constantTimeLessOrEq(2, 1));
    try testing.expectEqual(0, constantTimeLessOrEq(3, 2));
    try testing.expectEqual(0, constantTimeLessOrEq(255, 3));

    try testing.expectEqual(1, constantTimeLessOrEq(-255, 3));
    try testing.expectEqual(0, constantTimeLessOrEq(255, -3));
    try testing.expectEqual(1, constantTimeLessOrEq(-255, -3));
}

test "xorBytes" {
    {
        const x = [_]u8{ 1, 6, 7, 8, 8 };
        const y = [_]u8{ 1, 6, 7, 8, 32 };

        var res: [5]u8 = [_]u8{0} ** 5;

        try xorBytes(res[0..], x[0..], y[0..]);
        try testing.expectFmt("0000000028", "{x}", .{res});
    }

    {
        const x = [_]u8{ 1, 6, 7, 8, 8 };
        const y = [_]u8{ 1, 98, 7, 8, 32 };

        var res: [7]u8 = [_]u8{0} ** 7;

        try xorBytes(res[0..], x[0..], y[0..]);
        try testing.expectFmt("0064000028", "{x}", .{res[0..5]});
    }

    {
        const x = [_]u8{ 1, 6, 7, 8, 8 };
        const y = [_]u8{ 1, 98, 7, 8, 32, 12 };

        var res: [7]u8 = [_]u8{0} ** 7;

        try xorBytes(res[0..], x[0..], y[0..]);
        try testing.expectFmt("0064000028", "{x}", .{res[0..5]});
    }

    {
        const x = [_]u8{ 1, 6, 7, 8, 8, 0, 85, 8 };
        const y = [_]u8{ 1, 98, 7, 8, 32, 12, 7, 65, 12, 78 };

        var res: [7]u8 = [_]u8{0} ** 7;

        const res2 = xorBytes(res[0..], x[0..], y[0..]);
        try testing.expectError(error.DstTooShort, res2);
    }
}
