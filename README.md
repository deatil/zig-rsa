## Zig-rsa 

A RSA library for zig.


### Env

 - Zig >= 0.16.0


### Adding zig-rsa as a dependency

Add the dependency to your project:

```sh
zig fetch --save=zig-rsa git+https://github.com/deatil/zig-rsa#main
```

or use local path to add dependency at `build.zig.zon` file

```zig
.{
    .dependencies = .{
        .@"zig-rsa" = .{
            .path = "./lib/zig-rsa",
        },
        ...
    }
}
```

And the following to your `build.zig` file:

```zig
const zig_rsa_dep = b.dependency("zig-rsa", .{});
exe.root_module.addImport("zig-rsa", zig_rsa_dep.module("zig-rsa"));
```

The `zig-rsa` structure can be imported in your application with:

```zig
const rsa = @import("zig-rsa");
```


### Get Starting

~~~zig
const std = @import("std");
const rsa = @import("zig-rsa");

pub fn main(init: std.process.Init) !void {
    const alloc = init.arena.allocator();

    var prng = std.Random.DefaultPrng.init(0xC0FFEE_1234_5678);
    const random = prng.random();

    const kp = try rsa.KeyPair.generate(alloc, random, 1024);

    const msg = "hello rsa";

    const signature = try rsa.signPkcs1v15(alloc, kp.secret_key, TestHash, msg);
    defer alloc.free(signature);
    
    // output: 
    // rsa signPkcs1v15: 2ad0059bbd6d7e90c4c6e570611548e9125f6e36e94a0b331015aa960976b237f07ca880a44e52efb9d8aba96e63838f73d0aef9c18d9bf0728ece0bc94833bbfbb9cd57a9cca2133ce6eb872cb7f3747ffa89e94634ab589085f6a113c8e31a149ff6177d91d98f5e1af91ba3a4e4e9339d5bf50474f0c18483d0ee8ac1079a1dac9408e00a64907a9a43bce4273a5573c9f0d4814f0271eec465791f500b33ac1059899ee0ee643a3b9b6abe0980675dd8a3be26d61bef3f11f5ab5e9129276f6a8ddb9be958b3ea6413e38d79a5e9c025c0b488b8e4234b3d0807da36eb82d2c19f9fd95a71a4aff2f5219ba0e3b0df994c3129204d0e9c48d1e47bfb2edd
    std.debug.print("rsa signPkcs1v15: {x} \n", .{signature});

    const veri = rsa.verifyPkcs1v15(kp.public_key, TestHash, msg, signature);
    var status = true;
    if (veri) |_| {
        status = true;
    } else |_| {
        status = false;
    }

    // output: 
    // rsa verifyPkcs1v15: true
    std.debug.print("rsa verifyPkcs1v15: {} \n", .{});
}
~~~

### RSA functions

Generate key: 
~~~v
generate(alloc: Allocator, random: std.Random, bits: usize) !KeyPair
~~~

PKCS1v15 sign: 
~~~v
signPkcs1v15(
    alloc: Allocator,
    secret_key: SecretKey,
    comptime Hash: type,
    msg: []const u8,
) ![]u8
~~~

~~~v
verifyPkcs1v15(
    public_key: PublicKey,
    comptime Hash: type,
    msg: []const u8,
    sig: []u8,
) !void
~~~

PKCS1v15 encrypt: 
~~~v
encryptPkcs1v15(
    alloc: Allocator,
    random: std.Random,
    public_key: PublicKey,
    msg: []const u8,
) ![]const u8
~~~

~~~v
decryptPkcs1v15(alloc: Allocator, secret_key: SecretKey, ciphertext: []const u8) ![]const u8
~~~

OAEP encrypt: 
~~~v
encryptOaep(
    alloc: Allocator,
    random: std.Random,
    public_key: PublicKey,
    comptime Hash: type,
    msg: []const u8,
    label: []const u8,
) ![]const u8
~~~

~~~v
decryptOaep(
    alloc: Allocator,
    secret_key: SecretKey,
    comptime Hash: type,
    ciphertext: []const u8,
    label: []const u8,
) ![]const u8
~~~

PSS sign: 
~~~v
signPss(
    alloc: Allocator,
    random: std.Random,
    secret_key: SecretKey,
    comptime Hash: type,
    msg: []const u8,
    salt: ?[]const u8,
) ![]u8
~~~

~~~v
verifyPss(
    public_key: PublicKey,
    comptime Hash: type,
    msg: []const u8,
    sig: []u8,
    salt_len: ?usize,
) !void
~~~


### LICENSE

*  The library LICENSE is `Apache2`, using the library need keep the LICENSE.


### Copyright

*  Copyright deatil(https://github.com/deatil).
