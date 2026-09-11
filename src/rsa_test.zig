const std = @import("std");
const fmt = std.fmt;
const testing = std.testing;
const base64 = std.base64;
const hash = std.crypto.hash;
const codecs = std.crypto.codecs;
const Random = std.Random;
const Allocator = std.mem.Allocator;

const rsa = @import("rsa.zig");
const utils = @import("utils.zig");

const TestHash = std.crypto.hash.sha2.Sha256;

fn base64Decode(alloc: Allocator, input: []const u8) ![]const u8 {
    const decoder = base64.standard.Decoder;
    const decode_len = try decoder.calcSizeForSlice(input);

    const buffer = try alloc.alloc(u8, decode_len);
    _ = decoder.decode(buffer, input) catch {
        return "";
    };

    return buffer[0..];
}

fn hexDecode(alloc: Allocator, input: []const u8) ![]const u8 {
    const buffer = try alloc.alloc(u8, @divFloor(input.len, 2));
    _ = codecs.hex.decode(buffer, input) catch {
        return "";
    };

    return buffer[0..];
}

fn testKeypair() !rsa.KeyPair {
    const alloc = testing.allocator;

    const keypair_bytes = @embedFile("testdata/id_rsa.der");

    var sk = try rsa.SecretKey.fromDer(alloc, keypair_bytes);
    try sk.precompute(alloc);
    const kp = try rsa.KeyPair.fromSecretKey(sk);

    defer sk.deinit(alloc);

    try std.testing.expectEqual(2048, kp.public_key.n.bits());

    return kp;
}

test "rsa PKCS1-v1_5 encrypt and decrypt" {
    const alloc = testing.allocator;
    const io = testing.io;

    const random = utils.cryptoRand(io);

    const kp = try testKeypair();

    const msg = "rsa PKCS1-v1_5 encrypt and decrypt";
    const enc = try kp.public_key.encryptPkcs1v15(alloc, random, msg);
    const dec = try kp.secret_key.decryptPkcs1v15(alloc, enc);

    defer alloc.free(enc);
    defer alloc.free(dec);

    try std.testing.expectEqualSlices(u8, msg, dec);
    try std.testing.expectEqual(256, kp.public_key.size());

    // ==========

    const check2 = "907052e0ee7f8f92990751c3432c73a3450a7dece61ba1876169875dc9b28b4aa40699c8377141ed021a92c1ab623d734e8cf1010814eb7fc26321c7b037cc467c0f2b9029c4fc082387c7dedb718dda3251b3b2a7f06871d446be2df051e2013d3726af7002a5e487559cf36ea6a11bacdfb12dc35cc9285bfed8906fac3c0c8a1a69bbdc8f834e5f1a766e13792dcc202bf48e7eb6aca78f8df4904b59d2d09b5eaaf58903217b1d0d21fb66e5e44836b422500a2c9d5e0f37232544dc32a0d1ec33e32c4b113057441097f936a6e7b4f49be6b7fb7240b0f982aee9b3fde4708fb7dfe365b9576bcd0fd0120a50658c76c2e0361b82fbf60a423b363dd354";
    var enc2: [256]u8 = undefined;
    const enc2_res = try fmt.hexToBytes(&enc2, check2);

    const dec2 = try kp.secret_key.decryptPkcs1v15(alloc, enc2_res);

    defer alloc.free(dec2);

    try std.testing.expectEqualSlices(u8, msg, dec2);
}

test "rsa OAEP encrypt and decrypt" {
    const alloc = testing.allocator;
    const io = testing.io;

    const random = utils.cryptoRand(io);

    const kp = try testKeypair();

    const msg = "rsa OAEP encrypt and decrypt";
    const label = "";

    const enc = try kp.public_key.encryptOaep(alloc, random, TestHash, msg, label);
    const dec = try kp.secret_key.decryptOaep(alloc, TestHash, enc, label);

    defer alloc.free(enc);
    defer alloc.free(dec);

    try std.testing.expectEqualSlices(u8, msg, dec);

    // ==========

    const check2 = "76d93565b187e15d2b94b5c1ef9b715edde4c26a90e3045ada5ddad49718761ecd9dacc67ec4136d4b3ca9d236a0cd595bc6a14adde39bc4b75efbab0daa980d1525efd87ce526c66f9e225ddfdb85a2cffcf05bdd9ddff9a82f8a269339287cdac42a6a54580c6d2d7bcd07b332e304208e6f122c13f154abd56557eeb00b31a58df79ffec019dbe8681f4fe819c96fa4e030bdb63203c45ab9458d12660158bb9b0ef1a0c35a9954a73f89e59819fe7f2612d5728d863ce2d1e551a3da1fcc3e8f42c31e7da7918ff0ea9ed4b4e63e60ff066132b846ba9642d5ca9394fe99bf5bca1ce28ffcb81e54da28bced0eb85d046c7ccf150b2a3492b79abe72dd02";
    var enc2: [256]u8 = undefined;
    const enc2_res = try fmt.hexToBytes(&enc2, check2);

    const dec2 = try kp.secret_key.decryptOaep(alloc, TestHash, enc2_res, label);

    defer alloc.free(dec2);

    try std.testing.expectEqualSlices(u8, msg, dec2);
}

test "rsa PKCS1-v1_5 signature" {
    const alloc = testing.allocator;

    const kp = try testKeypair();

    const msg = "rsa PKCS1-v1_5 signature";

    var signature = try kp.signPkcs1v15(alloc, TestHash, msg);
    try signature.verify(msg, kp.public_key);

    defer signature.deinit(alloc);

    // ==========

    const check2 = "2ad0059bbd6d7e90c4c6e570611548e9125f6e36e94a0b331015aa960976b237f07ca880a44e52efb9d8aba96e63838f73d0aef9c18d9bf0728ece0bc94833bbfbb9cd57a9cca2133ce6eb872cb7f3747ffa89e94634ab589085f6a113c8e31a149ff6177d91d98f5e1af91ba3a4e4e9339d5bf50474f0c18483d0ee8ac1079a1dac9408e00a64907a9a43bce4273a5573c9f0d4814f0271eec465791f500b33ac1059899ee0ee643a3b9b6abe0980675dd8a3be26d61bef3f11f5ab5e9129276f6a8ddb9be958b3ea6413e38d79a5e9c025c0b488b8e4234b3d0807da36eb82d2c19f9fd95a71a4aff2f5219ba0e3b0df994c3129204d0e9c48d1e47bfb2edd";
    var sig2: [256]u8 = undefined;
    const sig2_res = try fmt.hexToBytes(&sig2, check2);

    var signature2 = rsa.PKCS1v15(TestHash).Signature.fromBytes(sig2_res);
    try signature2.verify(msg, kp.public_key);
}

test "rsa PKCS1-v1_5 signature fail" {
    const kp = try testKeypair();

    const msg = "rsa PKCS1-v1_5 signature";

    const check2 = "3ad0059bbd6d7e90c4c6e570611548e9125f6e36e94a0b331015aa960976b237f07ca880a44e52efb9d8aba96e63838f73d0aef9c18d9bf0728ece0bc94833bbfbb9cd57a9cca2133ce6eb872cb7f3747ffa89e94634ab589085f6a113c8e31a149ff6177d91d98f5e1af91ba3a4e4e9339d5bf50474f0c18483d0ee8ac1079a1dac9408e00a64907a9a43bce4273a5573c9f0d4814f0271eec465791f500b33ac1059899ee0ee643a3b9b6abe0980675dd8a3be26d61bef3f11f5ab5e9129276f6a8ddb9be958b3ea6413e38d79a5e9c025c0b488b8e4234b3d0807da36eb82d2c19f9fd95a71a4aff2f5219ba0e3b0df994c3129204d0e9c48d1e47bfb2edd";
    var sig2: [256]u8 = undefined;
    const sig2_res = try fmt.hexToBytes(&sig2, check2);

    const signature2 = rsa.PKCS1v15(TestHash).Signature.fromBytes(sig2_res);

    var need_true: bool = false;
    _ = signature2.verify(msg, kp.public_key) catch {
        need_true = true;
    };
    try testing.expectEqual(true, need_true);
}

test "rsa PSS signature" {
    const alloc = testing.allocator;
    const io = testing.io;

    const random = utils.cryptoRand(io);

    const kp = try testKeypair();

    const msg = "rsa PSS signature";

    const salts = [_][]const u8{ "asdf", "" };
    for (salts) |salt| {
        var signature = try kp.signPss(alloc, random, TestHash, msg, .{
            .salt = salt,
        });
        try signature.verify(msg, kp.public_key, .{
            .salt_leng = @as(isize, @intCast(salt.len)),
        });
        defer signature.deinit(alloc);
    }

    var signature = try kp.signPss(alloc, random, TestHash, msg, .{
        .salt_leng = rsa.pss_salt_length_equals_hash,
    }); // random salt
    try signature.verify(msg, kp.public_key, .{
        .salt_leng = rsa.pss_salt_length_equals_hash,
    });
    defer signature.deinit(alloc);

    // ==========

    const check2 = "6ae741a696a9eb8e79139ad9f8def16b4314fcda2cbca108d70e8555f5b2cbee2adc65bb91ec334e817108914d04cdcb8dd915dabfe5f2fb591e72c26553085e9731ccffa682539230bde35b4f43284be424a2f6b5f424649e2624454c3f9d93518f7d6fde6288962a50aace7f826d85ec23de2c2c6ddb470a20a4ad21c6f39c838a28a062d4359ffa00de3170ec018118bcd5e7ec6c6f658d1373caf0d1fdf4671058c2a67cfeb8b673188d34a28d9b0741e21ed5ef2ab7863b817271441ea4373601cb1064e654f9b88b4f9b83d9754fee19bf5e1924da49caafd34aafcbde9cd8d16ec5282e8f3abab2817664f6a4ff5f18e4d77c5a7f80df9f5538fd8c53";
    var sig2: [256]u8 = undefined;
    const sig2_res = try fmt.hexToBytes(&sig2, check2);

    const signature2 = rsa.Pss(TestHash).Signature.fromBytes(sig2_res);
    try signature2.verify(msg, kp.public_key, .{});
}

test "Signer with pkcs8 key" {
    const alloc = testing.allocator;
    const io = testing.io;

    const random = utils.cryptoRand(io);

    const prikey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDh/nCDmXaEqxN416b9XjV8acmbqA52uPzKbesWQRT/BPxEO2dKAURk5CkcSBDskvfzFR9TRjeDppjD1BPSEnuYKnP0SvmotoxcnBnHMfMBqGV8DSJyppu8k4y9C3MPq5C/rA8TJm0NNaJCL0BfAGkeyw+elgYifbRlm42VfYGsKVyIeEI9Qghk5Cf8yapMPfWNLKOhChXsyGExMBMonHZeseFH7UNwonNAFJMAaelhVqqmwBFqn6fBGKmvedRO7HIaiEFNKaMna6xJ5Bccjds4MhF7UC5PIdx4Bt7CfxvjrbIRYoBF2l30CNBblIhU992zPkHoaVhDkt1gq3OdO7LvAgMBAAECggEBALCJrWTv7ahnZ3efpqAIBuogTVBd8KaHjVmokds5jehFAbdfXClwYfgaT477MNVNXYmzN1w63sTl0DIxqiYRMCFHEHuGUg6cQ3tYqb50Y2spG9XTANTlF4UxEeDfX8ue7xz7kG8aNlf6TL084iEUVgmrAJGWikZJQjGZWPmtKC3OTeJY5Bev5qHVuMRe+XEM5aQc3ph+lXlOF0Qp0Eg8YRWprrev2faH6prMqu2JGomoac6sfM4QJhtEViF7Gw0XPthPTbF19IefuAwi9psMM/9CnQ+MTWN2i6IxoUdicsFuC+Wdlb3K5V/+uldNSr+ePEhcya+YTLK9IOcVwWKQHykCgYEA8XvuEribf+t0ZPtfxr+DC9nZHXbVoFx0/ARpSG+P/fp3Hn3rO9iYQ6OtZ9mEXTzf+dhYTaRWq6PbCOz6i0It+J8QSBdxU9OcQ4871mDe41IvSc1CCGMW4PeIYtNQEK0zrqhN7SMtKyUd7yAsYRCrIzMc7NjE2qJvFw5kh7xC3Q0CgYEA75Qjn5daNYSAOa/ILdOs5J/8oIaO27RNK/fSKm/btsMsyum8+YP/mWmm1MXBzG9WEKzZv5yEKOWCEVJYVsFQsGt9yLYW2WIKU5UxiuU0F1RImF/dphIbYOh7oGC3WfYKk2f+K7ftjc196ZkEkDuE2Xh1h75/67Mzztx1DbXj6OsCgYBcDRfFfyWXb5Og4smxo1M680H2H1RzmorlfnD7sbs733wE3Y8L8xanwf7Z9WqleA0Q2k1e22RGbWGTV3JyHzoS6d90+6qxf5qzjigLIkYUdUGdambfd5ZDD1ioA1Ej6kInM/TwjlYreiyc+LCyF36FHnjKOB9iEEU0jsH3k+YRCQKBgHMVLPuHX6zfhhyvxK/Gw4FbHKYbnNoKxRs+wvThoKAtJwIdv0n4TzppVttUV2CVhrkh3sM9MvrWLGGXtZmO6Oyl5dkZJuarQpydyRuYOCqQsQKI4lbY0c/+PQxwCQMsvi3KwXxMsM7yC+6/M0L5ZDp2s7ZOGvKktVlD6vJ4Eg+bAoGARnGGprSBW8dAb/s53r0paPh4k/bySrXdGEprLwk6g3S8+aylcmjUdjcIq4dEb4A/nv12dx1Sc4y99c62R0zi+TT6FYBIFDMz3HNVzO0Jr6SgC6CNVotL0D725CioR5U1NyTHHRLZth69HLuEZCZQlPJCbePXMRRHmOl1svzcVuo=";
    const pubkey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";

    const prikey_bytes = try base64Decode(alloc, prikey);
    const pubkey_bytes = try base64Decode(alloc, pubkey);

    defer alloc.free(prikey_bytes);
    defer alloc.free(pubkey_bytes);

    var pri_key = try rsa.SecretKey.fromPKCS8Der(alloc, prikey_bytes);
    const pub_key = try rsa.PublicKey.fromPKCS8Der(pubkey_bytes);

    defer pri_key.deinit(alloc);

    const msg = "rsa PSS signature";

    var sig = rsa.Pss(TestHash).Signer.init(alloc, random, pri_key, .{});
    sig.update(msg);
    const signed = try sig.finalize();

    const signed_bytes = signed.toBytes();
    try testing.expectEqual(true, signed_bytes.len > 0);

    defer alloc.free(signed_bytes);

    try signed.verify(msg, pub_key, .{});
}

test "Signer with pkcs8 key or pkcs1 key" {
    {
        // pkcs1 der key
        const prikey = "MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAyMaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdEKdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gMIvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDnFcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvYmEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghjFuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+UI5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNTOvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL04aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0KcnckbmDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ryeBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq";
        const pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";

        try test_sign_with_key_der(prikey, pubkey);
    }

    {
        // pkcs8 der key
        const prikey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDh/nCDmXaEqxN416b9XjV8acmbqA52uPzKbesWQRT/BPxEO2dKAURk5CkcSBDskvfzFR9TRjeDppjD1BPSEnuYKnP0SvmotoxcnBnHMfMBqGV8DSJyppu8k4y9C3MPq5C/rA8TJm0NNaJCL0BfAGkeyw+elgYifbRlm42VfYGsKVyIeEI9Qghk5Cf8yapMPfWNLKOhChXsyGExMBMonHZeseFH7UNwonNAFJMAaelhVqqmwBFqn6fBGKmvedRO7HIaiEFNKaMna6xJ5Bccjds4MhF7UC5PIdx4Bt7CfxvjrbIRYoBF2l30CNBblIhU992zPkHoaVhDkt1gq3OdO7LvAgMBAAECggEBALCJrWTv7ahnZ3efpqAIBuogTVBd8KaHjVmokds5jehFAbdfXClwYfgaT477MNVNXYmzN1w63sTl0DIxqiYRMCFHEHuGUg6cQ3tYqb50Y2spG9XTANTlF4UxEeDfX8ue7xz7kG8aNlf6TL084iEUVgmrAJGWikZJQjGZWPmtKC3OTeJY5Bev5qHVuMRe+XEM5aQc3ph+lXlOF0Qp0Eg8YRWprrev2faH6prMqu2JGomoac6sfM4QJhtEViF7Gw0XPthPTbF19IefuAwi9psMM/9CnQ+MTWN2i6IxoUdicsFuC+Wdlb3K5V/+uldNSr+ePEhcya+YTLK9IOcVwWKQHykCgYEA8XvuEribf+t0ZPtfxr+DC9nZHXbVoFx0/ARpSG+P/fp3Hn3rO9iYQ6OtZ9mEXTzf+dhYTaRWq6PbCOz6i0It+J8QSBdxU9OcQ4871mDe41IvSc1CCGMW4PeIYtNQEK0zrqhN7SMtKyUd7yAsYRCrIzMc7NjE2qJvFw5kh7xC3Q0CgYEA75Qjn5daNYSAOa/ILdOs5J/8oIaO27RNK/fSKm/btsMsyum8+YP/mWmm1MXBzG9WEKzZv5yEKOWCEVJYVsFQsGt9yLYW2WIKU5UxiuU0F1RImF/dphIbYOh7oGC3WfYKk2f+K7ftjc196ZkEkDuE2Xh1h75/67Mzztx1DbXj6OsCgYBcDRfFfyWXb5Og4smxo1M680H2H1RzmorlfnD7sbs733wE3Y8L8xanwf7Z9WqleA0Q2k1e22RGbWGTV3JyHzoS6d90+6qxf5qzjigLIkYUdUGdambfd5ZDD1ioA1Ej6kInM/TwjlYreiyc+LCyF36FHnjKOB9iEEU0jsH3k+YRCQKBgHMVLPuHX6zfhhyvxK/Gw4FbHKYbnNoKxRs+wvThoKAtJwIdv0n4TzppVttUV2CVhrkh3sM9MvrWLGGXtZmO6Oyl5dkZJuarQpydyRuYOCqQsQKI4lbY0c/+PQxwCQMsvi3KwXxMsM7yC+6/M0L5ZDp2s7ZOGvKktVlD6vJ4Eg+bAoGARnGGprSBW8dAb/s53r0paPh4k/bySrXdGEprLwk6g3S8+aylcmjUdjcIq4dEb4A/nv12dx1Sc4y99c62R0zi+TT6FYBIFDMz3HNVzO0Jr6SgC6CNVotL0D725CioR5U1NyTHHRLZth69HLuEZCZQlPJCbePXMRRHmOl1svzcVuo=";
        const pubkey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";

        try test_sign_with_key_der(prikey, pubkey);
    }
}

fn test_sign_with_key_der(prikey: []const u8, pubkey: []const u8) !void {
    const alloc = testing.allocator;
    const io = testing.io;

    const random = utils.cryptoRand(io);

    const prikey_bytes = try base64Decode(alloc, prikey);
    const pubkey_bytes = try base64Decode(alloc, pubkey);

    defer alloc.free(prikey_bytes);
    defer alloc.free(pubkey_bytes);

    var pri_key = try rsa.SecretKey.fromDerAuto(alloc, prikey_bytes);
    const pub_key = try rsa.PublicKey.fromDerAuto(pubkey_bytes);

    defer pri_key.deinit(alloc);

    try std.testing.expectEqual(256, pri_key.public_key.size());
    try std.testing.expectEqual(256, pub_key.size());

    const msg = "rsa PSS signature";

    var sig = rsa.Pss(TestHash).Signer.init(alloc, random, pri_key, .{});
    sig.update(msg);
    const signed = try sig.finalize();

    const signed_bytes = signed.toBytes();
    try testing.expectEqual(true, signed_bytes.len > 0);

    defer alloc.free(signed_bytes);

    try signed.verify(msg, pub_key, .{});
}

test "SecretKey precompute" {
    const alloc = testing.allocator;

    const prikey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDh/nCDmXaEqxN416b9XjV8acmbqA52uPzKbesWQRT/BPxEO2dKAURk5CkcSBDskvfzFR9TRjeDppjD1BPSEnuYKnP0SvmotoxcnBnHMfMBqGV8DSJyppu8k4y9C3MPq5C/rA8TJm0NNaJCL0BfAGkeyw+elgYifbRlm42VfYGsKVyIeEI9Qghk5Cf8yapMPfWNLKOhChXsyGExMBMonHZeseFH7UNwonNAFJMAaelhVqqmwBFqn6fBGKmvedRO7HIaiEFNKaMna6xJ5Bccjds4MhF7UC5PIdx4Bt7CfxvjrbIRYoBF2l30CNBblIhU992zPkHoaVhDkt1gq3OdO7LvAgMBAAECggEBALCJrWTv7ahnZ3efpqAIBuogTVBd8KaHjVmokds5jehFAbdfXClwYfgaT477MNVNXYmzN1w63sTl0DIxqiYRMCFHEHuGUg6cQ3tYqb50Y2spG9XTANTlF4UxEeDfX8ue7xz7kG8aNlf6TL084iEUVgmrAJGWikZJQjGZWPmtKC3OTeJY5Bev5qHVuMRe+XEM5aQc3ph+lXlOF0Qp0Eg8YRWprrev2faH6prMqu2JGomoac6sfM4QJhtEViF7Gw0XPthPTbF19IefuAwi9psMM/9CnQ+MTWN2i6IxoUdicsFuC+Wdlb3K5V/+uldNSr+ePEhcya+YTLK9IOcVwWKQHykCgYEA8XvuEribf+t0ZPtfxr+DC9nZHXbVoFx0/ARpSG+P/fp3Hn3rO9iYQ6OtZ9mEXTzf+dhYTaRWq6PbCOz6i0It+J8QSBdxU9OcQ4871mDe41IvSc1CCGMW4PeIYtNQEK0zrqhN7SMtKyUd7yAsYRCrIzMc7NjE2qJvFw5kh7xC3Q0CgYEA75Qjn5daNYSAOa/ILdOs5J/8oIaO27RNK/fSKm/btsMsyum8+YP/mWmm1MXBzG9WEKzZv5yEKOWCEVJYVsFQsGt9yLYW2WIKU5UxiuU0F1RImF/dphIbYOh7oGC3WfYKk2f+K7ftjc196ZkEkDuE2Xh1h75/67Mzztx1DbXj6OsCgYBcDRfFfyWXb5Og4smxo1M680H2H1RzmorlfnD7sbs733wE3Y8L8xanwf7Z9WqleA0Q2k1e22RGbWGTV3JyHzoS6d90+6qxf5qzjigLIkYUdUGdambfd5ZDD1ioA1Ej6kInM/TwjlYreiyc+LCyF36FHnjKOB9iEEU0jsH3k+YRCQKBgHMVLPuHX6zfhhyvxK/Gw4FbHKYbnNoKxRs+wvThoKAtJwIdv0n4TzppVttUV2CVhrkh3sM9MvrWLGGXtZmO6Oyl5dkZJuarQpydyRuYOCqQsQKI4lbY0c/+PQxwCQMsvi3KwXxMsM7yC+6/M0L5ZDp2s7ZOGvKktVlD6vJ4Eg+bAoGARnGGprSBW8dAb/s53r0paPh4k/bySrXdGEprLwk6g3S8+aylcmjUdjcIq4dEb4A/nv12dx1Sc4y99c62R0zi+TT6FYBIFDMz3HNVzO0Jr6SgC6CNVotL0D725CioR5U1NyTHHRLZth69HLuEZCZQlPJCbePXMRRHmOl1svzcVuo=";

    const prikey_bytes = try base64Decode(alloc, prikey);

    defer alloc.free(prikey_bytes);

    var pri_key = try rsa.SecretKey.fromPKCS8DerWithPrecompute(alloc, prikey_bytes);

    defer pri_key.deinit(alloc);

    const dp = pri_key.precomputed.?.dp;
    const dq = pri_key.precomputed.?.dq;
    const qinv = pri_key.precomputed.?.qinv;

    var dpbuf: [rsa.max_modulus_len]u8 = undefined;
    try dp.toBytes(&dpbuf, .big);
    const new_dpbuf = utils.stripLeadingZeros(&dpbuf);

    var dqbuf: [rsa.max_modulus_len]u8 = undefined;
    try dq.toBytes(&dqbuf, .big);
    const new_dqbuf = utils.stripLeadingZeros(&dqbuf);

    var qinvbuf: [rsa.max_modulus_len]u8 = undefined;
    try qinv.toBytes(&qinvbuf, .big);
    const new_qinvbuf = utils.stripLeadingZeros(&qinvbuf);

    try testing.expectFmt("5c0d17c57f25976f93a0e2c9b1a3533af341f61f54739a8ae57e70fbb1bb3bdf7c04dd8f0bf316a7c1fed9f56aa5780d10da4d5edb64466d61935772721f3a12e9df74fbaab17f9ab38e280b22461475419d6a66df7796430f58a8035123ea422733f4f08e562b7a2c9cf8b0b2177e851e78ca381f621045348ec1f793e61109", "{x}", .{new_dpbuf});
    try testing.expectFmt("73152cfb875facdf861cafc4afc6c3815b1ca61b9cda0ac51b3ec2f4e1a0a02d27021dbf49f84f3a6956db5457609586b921dec33d32fad62c6197b5998ee8eca5e5d91926e6ab429c9dc91b98382a90b10288e256d8d1cffe3d0c7009032cbe2dcac17c4cb0cef20beebf3342f9643a76b3b64e1af2a4b55943eaf278120f9b", "{x}", .{new_dqbuf});
    try testing.expectFmt("467186a6b4815bc7406ffb39debd2968f87893f6f24ab5dd184a6b2f093a8374bcf9aca57268d4763708ab87446f803f9efd76771d52738cbdf5ceb6474ce2f934fa158048143333dc7355cced09afa4a00ba08d568b4bd03ef6e428a84795353724c71d12d9b61ebd1cbb8464265094f2426de3d731144798e975b2fcdc56ea", "{x}", .{new_qinvbuf});
}

test "SecretKey validate" {
    const alloc = testing.allocator;

    const prikey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDh/nCDmXaEqxN416b9XjV8acmbqA52uPzKbesWQRT/BPxEO2dKAURk5CkcSBDskvfzFR9TRjeDppjD1BPSEnuYKnP0SvmotoxcnBnHMfMBqGV8DSJyppu8k4y9C3MPq5C/rA8TJm0NNaJCL0BfAGkeyw+elgYifbRlm42VfYGsKVyIeEI9Qghk5Cf8yapMPfWNLKOhChXsyGExMBMonHZeseFH7UNwonNAFJMAaelhVqqmwBFqn6fBGKmvedRO7HIaiEFNKaMna6xJ5Bccjds4MhF7UC5PIdx4Bt7CfxvjrbIRYoBF2l30CNBblIhU992zPkHoaVhDkt1gq3OdO7LvAgMBAAECggEBALCJrWTv7ahnZ3efpqAIBuogTVBd8KaHjVmokds5jehFAbdfXClwYfgaT477MNVNXYmzN1w63sTl0DIxqiYRMCFHEHuGUg6cQ3tYqb50Y2spG9XTANTlF4UxEeDfX8ue7xz7kG8aNlf6TL084iEUVgmrAJGWikZJQjGZWPmtKC3OTeJY5Bev5qHVuMRe+XEM5aQc3ph+lXlOF0Qp0Eg8YRWprrev2faH6prMqu2JGomoac6sfM4QJhtEViF7Gw0XPthPTbF19IefuAwi9psMM/9CnQ+MTWN2i6IxoUdicsFuC+Wdlb3K5V/+uldNSr+ePEhcya+YTLK9IOcVwWKQHykCgYEA8XvuEribf+t0ZPtfxr+DC9nZHXbVoFx0/ARpSG+P/fp3Hn3rO9iYQ6OtZ9mEXTzf+dhYTaRWq6PbCOz6i0It+J8QSBdxU9OcQ4871mDe41IvSc1CCGMW4PeIYtNQEK0zrqhN7SMtKyUd7yAsYRCrIzMc7NjE2qJvFw5kh7xC3Q0CgYEA75Qjn5daNYSAOa/ILdOs5J/8oIaO27RNK/fSKm/btsMsyum8+YP/mWmm1MXBzG9WEKzZv5yEKOWCEVJYVsFQsGt9yLYW2WIKU5UxiuU0F1RImF/dphIbYOh7oGC3WfYKk2f+K7ftjc196ZkEkDuE2Xh1h75/67Mzztx1DbXj6OsCgYBcDRfFfyWXb5Og4smxo1M680H2H1RzmorlfnD7sbs733wE3Y8L8xanwf7Z9WqleA0Q2k1e22RGbWGTV3JyHzoS6d90+6qxf5qzjigLIkYUdUGdambfd5ZDD1ioA1Ej6kInM/TwjlYreiyc+LCyF36FHnjKOB9iEEU0jsH3k+YRCQKBgHMVLPuHX6zfhhyvxK/Gw4FbHKYbnNoKxRs+wvThoKAtJwIdv0n4TzppVttUV2CVhrkh3sM9MvrWLGGXtZmO6Oyl5dkZJuarQpydyRuYOCqQsQKI4lbY0c/+PQxwCQMsvi3KwXxMsM7yC+6/M0L5ZDp2s7ZOGvKktVlD6vJ4Eg+bAoGARnGGprSBW8dAb/s53r0paPh4k/bySrXdGEprLwk6g3S8+aylcmjUdjcIq4dEb4A/nv12dx1Sc4y99c62R0zi+TT6FYBIFDMz3HNVzO0Jr6SgC6CNVotL0D725CioR5U1NyTHHRLZth69HLuEZCZQlPJCbePXMRRHmOl1svzcVuo=";

    const prikey_bytes = try base64Decode(alloc, prikey);

    defer alloc.free(prikey_bytes);

    var pri_key = try rsa.SecretKey.fromPKCS8Der(alloc, prikey_bytes);
    defer pri_key.deinit(alloc);

    try pri_key.validate();
}

test "KeyPair generate" {
    const alloc = testing.allocator;
    const io = testing.io;

    const random = utils.cryptoRand(io);

    const kp = try rsa.KeyPair.generate(alloc, random, 1024);
    var secret_key = kp.secret_key;
    defer secret_key.deinit(alloc);

    const msg = "rsa PSS signature";

    var sig = rsa.Pss(TestHash).Signer.init(alloc, random, kp.secret_key, .{});
    sig.update(msg);
    const signed = try sig.finalize();

    const signed_bytes = signed.toBytes();
    try testing.expectEqual(true, signed_bytes.len > 0);

    defer alloc.free(signed_bytes);

    try signed.verify(msg, kp.public_key, .{});
}

test "rsa PKCS1-v1_5 function encrypt and decrypt" {
    const alloc = testing.allocator;
    const io = testing.io;

    const random = utils.cryptoRand(io);

    const kp = try testKeypair();

    const msg = "rsa PKCS1-v1_5 encrypt and decrypt";
    const enc = try rsa.encryptPkcs1v15(alloc, random, kp.public_key, msg);
    const dec = try rsa.decryptPkcs1v15(alloc, kp.secret_key, enc);

    defer alloc.free(enc);
    defer alloc.free(dec);

    try std.testing.expectEqualSlices(u8, msg, dec);

    // ==========

    const check2 = "907052e0ee7f8f92990751c3432c73a3450a7dece61ba1876169875dc9b28b4aa40699c8377141ed021a92c1ab623d734e8cf1010814eb7fc26321c7b037cc467c0f2b9029c4fc082387c7dedb718dda3251b3b2a7f06871d446be2df051e2013d3726af7002a5e487559cf36ea6a11bacdfb12dc35cc9285bfed8906fac3c0c8a1a69bbdc8f834e5f1a766e13792dcc202bf48e7eb6aca78f8df4904b59d2d09b5eaaf58903217b1d0d21fb66e5e44836b422500a2c9d5e0f37232544dc32a0d1ec33e32c4b113057441097f936a6e7b4f49be6b7fb7240b0f982aee9b3fde4708fb7dfe365b9576bcd0fd0120a50658c76c2e0361b82fbf60a423b363dd354";
    var enc2: [256]u8 = undefined;
    const enc2_res = try fmt.hexToBytes(&enc2, check2);

    const dec2 = try rsa.decryptPkcs1v15(alloc, kp.secret_key, enc2_res);
    defer alloc.free(dec2);

    try std.testing.expectEqualSlices(u8, msg, dec2);
}

test "rsa OAEP function encrypt and decrypt" {
    const alloc = testing.allocator;
    const io = testing.io;

    const random = utils.cryptoRand(io);

    const kp = try testKeypair();

    const msg = "rsa OAEP encrypt and decrypt";
    const label = "";
    const enc = try rsa.encryptOaep(alloc, random, kp.public_key, TestHash, msg, label);
    const dec = try rsa.decryptOaep(alloc, kp.secret_key, TestHash, enc, label);

    defer alloc.free(enc);
    defer alloc.free(dec);

    try std.testing.expectEqualSlices(u8, msg, dec);

    // ==========

    const check2 = "76d93565b187e15d2b94b5c1ef9b715edde4c26a90e3045ada5ddad49718761ecd9dacc67ec4136d4b3ca9d236a0cd595bc6a14adde39bc4b75efbab0daa980d1525efd87ce526c66f9e225ddfdb85a2cffcf05bdd9ddff9a82f8a269339287cdac42a6a54580c6d2d7bcd07b332e304208e6f122c13f154abd56557eeb00b31a58df79ffec019dbe8681f4fe819c96fa4e030bdb63203c45ab9458d12660158bb9b0ef1a0c35a9954a73f89e59819fe7f2612d5728d863ce2d1e551a3da1fcc3e8f42c31e7da7918ff0ea9ed4b4e63e60ff066132b846ba9642d5ca9394fe99bf5bca1ce28ffcb81e54da28bced0eb85d046c7ccf150b2a3492b79abe72dd02";
    var enc2: [256]u8 = undefined;
    const enc2_res = try fmt.hexToBytes(&enc2, check2);

    const dec2 = try rsa.decryptOaep(alloc, kp.secret_key, TestHash, enc2_res, label);
    defer alloc.free(dec2);

    try std.testing.expectEqualSlices(u8, msg, dec2);
}

test "rsa PKCS1-v1_5 function signature" {
    const alloc = testing.allocator;

    const kp = try testKeypair();

    const msg = "rsa PKCS1-v1_5 signature";

    const signature = try rsa.signPkcs1v15(alloc, kp.secret_key, TestHash, msg);
    try rsa.verifyPkcs1v15(kp.public_key, TestHash, msg, signature);

    defer alloc.free(signature);

    // ==========

    const check2 = "2ad0059bbd6d7e90c4c6e570611548e9125f6e36e94a0b331015aa960976b237f07ca880a44e52efb9d8aba96e63838f73d0aef9c18d9bf0728ece0bc94833bbfbb9cd57a9cca2133ce6eb872cb7f3747ffa89e94634ab589085f6a113c8e31a149ff6177d91d98f5e1af91ba3a4e4e9339d5bf50474f0c18483d0ee8ac1079a1dac9408e00a64907a9a43bce4273a5573c9f0d4814f0271eec465791f500b33ac1059899ee0ee643a3b9b6abe0980675dd8a3be26d61bef3f11f5ab5e9129276f6a8ddb9be958b3ea6413e38d79a5e9c025c0b488b8e4234b3d0807da36eb82d2c19f9fd95a71a4aff2f5219ba0e3b0df994c3129204d0e9c48d1e47bfb2edd";
    var sig2: [256]u8 = undefined;
    const sig2_res = try fmt.hexToBytes(&sig2, check2);

    try rsa.verifyPkcs1v15(kp.public_key, TestHash, msg, sig2_res);
}

test "rsa PKCS1-v1_5 function signature fail" {
    const kp = try testKeypair();

    const msg = "rsa PKCS1-v1_5 signature";

    const check2 = "3ad0059bbd6d7e90c4c6e570611548e9125f6e36e94a0b331015aa960976b237f07ca880a44e52efb9d8aba96e63838f73d0aef9c18d9bf0728ece0bc94833bbfbb9cd57a9cca2133ce6eb872cb7f3747ffa89e94634ab589085f6a113c8e31a149ff6177d91d98f5e1af91ba3a4e4e9339d5bf50474f0c18483d0ee8ac1079a1dac9408e00a64907a9a43bce4273a5573c9f0d4814f0271eec465791f500b33ac1059899ee0ee643a3b9b6abe0980675dd8a3be26d61bef3f11f5ab5e9129276f6a8ddb9be958b3ea6413e38d79a5e9c025c0b488b8e4234b3d0807da36eb82d2c19f9fd95a71a4aff2f5219ba0e3b0df994c3129204d0e9c48d1e47bfb2edd";
    var sig2: [256]u8 = undefined;
    const sig2_res = try fmt.hexToBytes(&sig2, check2);

    var need_err: bool = false;
    _ = rsa.verifyPkcs1v15(kp.public_key, TestHash, msg, sig2_res) catch {
        need_err = true;
    };
    try testing.expectEqual(true, need_err);
}

test "rsa PSS function signature" {
    const alloc = testing.allocator;
    const io = testing.io;

    const random = utils.cryptoRand(io);

    const kp = try testKeypair();

    const msg = "rsa PSS signature";

    const salts = [_][]const u8{ "asdf", "" };
    for (salts) |salt| {
        const signature = try rsa.signPss(alloc, random, kp.secret_key, TestHash, msg, .{
            .salt = salt,
        });
        try rsa.verifyPss(kp.public_key, TestHash, msg, signature, .{
            .salt_leng = @as(isize, @intCast(salt.len)),
        });

        defer alloc.free(signature);
    }

    const signature = try rsa.signPss(alloc, random, kp.secret_key, TestHash, msg, .{}); // random salt
    try rsa.verifyPss(kp.public_key, TestHash, msg, signature, .{
        .salt_leng = rsa.pss_salt_length_auto,
    });

    defer alloc.free(signature);

    // ==========

    const check2 = "6ae741a696a9eb8e79139ad9f8def16b4314fcda2cbca108d70e8555f5b2cbee2adc65bb91ec334e817108914d04cdcb8dd915dabfe5f2fb591e72c26553085e9731ccffa682539230bde35b4f43284be424a2f6b5f424649e2624454c3f9d93518f7d6fde6288962a50aace7f826d85ec23de2c2c6ddb470a20a4ad21c6f39c838a28a062d4359ffa00de3170ec018118bcd5e7ec6c6f658d1373caf0d1fdf4671058c2a67cfeb8b673188d34a28d9b0741e21ed5ef2ab7863b817271441ea4373601cb1064e654f9b88b4f9b83d9754fee19bf5e1924da49caafd34aafcbde9cd8d16ec5282e8f3abab2817664f6a4ff5f18e4d77c5a7f80df9f5538fd8c53";
    var sig2: [256]u8 = undefined;
    const sig2_res = try fmt.hexToBytes(&sig2, check2);

    try rsa.verifyPss(kp.public_key, TestHash, msg, sig2_res, .{
        .salt_leng = rsa.pss_salt_length_auto,
    });
}

test "rsa PSS function signature with generate_key" {
    const alloc = testing.allocator;
    const io = testing.io;

    const random = utils.cryptoRand(io);

    const kp = try rsa.generate_key(alloc, random, 1024);

    var secret_key = kp.secret_key;
    defer secret_key.deinit(alloc);

    const msg = "rsa PSS function signature";

    {
        const signature = try rsa.signPss(alloc, random, kp.secret_key, TestHash, msg, .{}); // random salt
        try rsa.verifyPss(kp.public_key, TestHash, msg, signature, .{
            .salt_leng = rsa.pss_salt_length_auto,
        });

        defer alloc.free(signature);
    }

    {
        const signature = try rsa.signPss(alloc, random, kp.secret_key, TestHash, msg, .{
            .salt_leng = rsa.pss_salt_length_auto,
        });
        try rsa.verifyPss(kp.public_key, TestHash, msg, signature, .{
            .salt_leng = rsa.pss_salt_length_auto,
        });

        defer alloc.free(signature);
    }

    {
        const signature = try rsa.signPss(alloc, random, kp.secret_key, TestHash, msg, .{
            .salt_leng = rsa.pss_salt_length_equals_hash,
        });
        try rsa.verifyPss(kp.public_key, TestHash, msg, signature, .{
            .salt_leng = rsa.pss_salt_length_equals_hash,
        });

        defer alloc.free(signature);
    }

    {
        const signature = try rsa.signPss(alloc, random, kp.secret_key, TestHash, msg, .{
            .salt_leng = rsa.pss_salt_length_equals_hash,
        });
        try rsa.verifyPss(kp.public_key, TestHash, msg, signature, .{
            .salt_leng = rsa.pss_salt_length_auto,
        });

        defer alloc.free(signature);
    }

    {
        const signature = try rsa.signPss(alloc, random, kp.secret_key, TestHash, msg, .{
            .salt = "salt test",
        });
        try rsa.verifyPss(kp.public_key, TestHash, msg, signature, .{
            .salt_leng = rsa.pss_salt_length_auto,
        });

        defer alloc.free(signature);
    }

    {
        const signature = try rsa.signPss(alloc, random, kp.secret_key, TestHash, msg, .{
            .salt = "salt test",
        });

        var need_err = false;
        rsa.verifyPss(kp.public_key, TestHash, msg, signature, .{
            .salt_leng = rsa.pss_salt_length_equals_hash,
        }) catch {
            need_err = true;
        };
        try testing.expectEqual(true, need_err);

        defer alloc.free(signature);
    }

    {
        const signature = try rsa.signPss(alloc, random, kp.secret_key, TestHash, msg, .{
            .salt_leng = 8,
        });
        try rsa.verifyPss(kp.public_key, TestHash, msg, signature, .{
            .salt_leng = 8,
        });

        defer alloc.free(signature);
    }

    {
        const signature = try rsa.signPss(alloc, random, kp.secret_key, TestHash, msg, .{
            .salt_leng = -3,
        });
        try rsa.verifyPss(kp.public_key, TestHash, msg, signature, .{
            .salt_leng = -3,
        });

        defer alloc.free(signature);
    }
}

fn test_sign_pkcs1v15_with_hash(kp: rsa.KeyPair, comptime h: type) !void {
    const alloc = testing.allocator;

    const msg = "rsa PKCS1-v1_5 signature";

    const signature = try rsa.signPkcs1v15(alloc, kp.secret_key, h, msg);
    try rsa.verifyPkcs1v15(kp.public_key, h, msg, signature);

    defer alloc.free(signature);
}

test "rsa PKCS1-v1_5 function signature with hash" {
    const kp = try testKeypair();

    const sha2 = hash.sha2;
    const sha3 = hash.sha3;

    try test_sign_pkcs1v15_with_hash(kp, hash.Md5);
    try test_sign_pkcs1v15_with_hash(kp, hash.Sha1);

    try test_sign_pkcs1v15_with_hash(kp, sha2.Sha224);
    try test_sign_pkcs1v15_with_hash(kp, sha2.Sha256);
    try test_sign_pkcs1v15_with_hash(kp, sha2.Sha384);
    try test_sign_pkcs1v15_with_hash(kp, sha2.Sha512);
    try test_sign_pkcs1v15_with_hash(kp, sha2.Sha512_224);
    try test_sign_pkcs1v15_with_hash(kp, sha2.Sha512_256);

    try test_sign_pkcs1v15_with_hash(kp, sha3.Sha3_224);
    try test_sign_pkcs1v15_with_hash(kp, sha3.Sha3_256);
    try test_sign_pkcs1v15_with_hash(kp, sha3.Sha3_384);
    try test_sign_pkcs1v15_with_hash(kp, sha3.Sha3_512);
}

test "rsa OAEP function encrypt and decrypt with options" {
    const alloc = testing.allocator;
    const io = testing.io;

    const random = utils.cryptoRand(io);

    const sha2 = std.crypto.hash.sha2;

    const kp = try testKeypair();

    const msg = "rsa OAEP encrypt and decrypt";
    const label = "";

    {
        const enc = try rsa.encryptOaepWithOptions(alloc, random, kp.public_key, msg, .{
            .hash = TestHash,
            .label = label,
        });
        const dec = try rsa.decryptOaepWithOptions(alloc, kp.secret_key, enc, .{
            .hash = TestHash,
            .label = label,
        });

        defer alloc.free(enc);
        defer alloc.free(dec);

        try std.testing.expectEqualSlices(u8, msg, dec);
    }

    {
        const enc = try rsa.encryptOaepWithOptions(alloc, random, kp.public_key, msg, .{
            .hash = sha2.Sha256,
            .mgf_hash = sha2.Sha384,
            .label = label,
        });
        const dec = try rsa.decryptOaepWithOptions(alloc, kp.secret_key, enc, .{
            .hash = sha2.Sha256,
            .mgf_hash = sha2.Sha384,
            .label = label,
        });

        defer alloc.free(enc);
        defer alloc.free(dec);

        try std.testing.expectEqualSlices(u8, msg, dec);
    }

    {
        const check2 = "76d93565b187e15d2b94b5c1ef9b715edde4c26a90e3045ada5ddad49718761ecd9dacc67ec4136d4b3ca9d236a0cd595bc6a14adde39bc4b75efbab0daa980d1525efd87ce526c66f9e225ddfdb85a2cffcf05bdd9ddff9a82f8a269339287cdac42a6a54580c6d2d7bcd07b332e304208e6f122c13f154abd56557eeb00b31a58df79ffec019dbe8681f4fe819c96fa4e030bdb63203c45ab9458d12660158bb9b0ef1a0c35a9954a73f89e59819fe7f2612d5728d863ce2d1e551a3da1fcc3e8f42c31e7da7918ff0ea9ed4b4e63e60ff066132b846ba9642d5ca9394fe99bf5bca1ce28ffcb81e54da28bced0eb85d046c7ccf150b2a3492b79abe72dd02";
        var enc2: [256]u8 = undefined;
        const enc2_res = try fmt.hexToBytes(&enc2, check2);

        const dec2 = try rsa.decryptOaepWithOptions(alloc, kp.secret_key, enc2_res, .{
            .hash = TestHash,
            .label = label,
        });
        defer alloc.free(dec2);

        try std.testing.expectEqualSlices(u8, msg, dec2);
    }

    {
        const prikey = "MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAyMaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdEKdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gMIvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDnFcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvYmEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghjFuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+UI5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNTOvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL04aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0KcnckbmDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ryeBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq";
        const prikey_bytes = try base64Decode(alloc, prikey);
        defer alloc.free(prikey_bytes);

        var pri_key = try rsa.SecretKey.fromDer(alloc, prikey_bytes);
        try pri_key.precompute(alloc);

        defer pri_key.deinit(alloc);

        const check2 = "d1c26a4556c1e747c0388eec95785f38840ea37b55b8577bafc2f59e079da4e7712916839d3b1d9c12bb2a9869ead29471968c8e09d9b7f40587fc4a480cc19d908ff2d76102da695cfd2d4d33d2f1c96450ba1f99532bce9945fba0410ed88e25e648e536200fd6d46152d999034ad561c1086dcdbd7f3ce8aa9617f73efdaa75ddf88888184323c2beefc27822729cc19bc5d3018e76f6a380b6d012a9fd4cb42ba702df06ab8201243b99c5d337824d92178f69458216473c439d6ff2417a32dffbf138061e4e7f97dc72a8dea6bf45a64c6ab2a1105655bf36dd71b3bd6fa38041556d0fd4a8193194ce1ceb78bf3cd5e6bbfa763eb36afe2f146960de0c";
        var enc2: [256]u8 = undefined;
        const enc2_res = try fmt.hexToBytes(&enc2, check2);

        const dec2 = try rsa.decryptOaepWithOptions(alloc, pri_key, enc2_res, .{
            .hash = sha2.Sha384,
            .mgf_hash = sha2.Sha256,
            .label = "label-test",
        });
        defer alloc.free(dec2);

        const msg2 = "message-data";
        try std.testing.expectEqualSlices(u8, msg2, dec2);
    }
}

test "rsa list check" {
    const alloc = testing.allocator;

    const prikey = "MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAyMaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdEKdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gMIvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDnFcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvYmEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghjFuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+UI5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNTOvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL04aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0KcnckbmDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ryeBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq";
    const prikey_bytes = try base64Decode(alloc, prikey);
    defer alloc.free(prikey_bytes);

    var pri_key = try rsa.SecretKey.fromDerWithPrecompute(alloc, prikey_bytes);
    defer pri_key.deinit(alloc);

    const pub_key = pri_key.public_key;

    const sha2 = std.crypto.hash.sha2;
    const msg = "message-data";

    {
        const check2 = "25d14fe04e66c8da872bc54a80ddd3f36c5de3aa9540efb9475b74f62e1f4112ca22f679dbbb3d74a485facea7ea2efcf4404aa3c52418ec4c6c2e7592f868cb64d07f16576ccea344aeaaf6f365fa982bc83c6c9bd70564789e879ab8a4eba6a561a5f289a20453801f16fc79b2b676c0b23e6b530b673bc7a0aff8c4b4a8148e903e7afd6a871dfc70466b1a031068ae583f883de6c94e1d944b73c6cf87269c9bd14120ead9fca8360f5a247747f42d54935927b9dd0ad25821e5f3f2542b22267de397045bf7429f662020759629f71d12c7f91663bc856724685b67a1cd800f398e7378ed1747830bc94d5240d76f5538d505856a1138ebc613b34acdab";
        var sig2: [256]u8 = undefined;
        const sig2_res = try fmt.hexToBytes(&sig2, check2);

        try rsa.verifyPkcs1v15(pub_key, sha2.Sha256, msg, sig2_res);
    }

    {
        const check2 = "61bfa956b12ee62fa056c819f2980e342d2bac5244dc4775b1fc849f7b56aa66fb01e0b95d9393070e04e82c8b71c5676542cbb981976954b710d7277655f70bcc132d71d5d1a861d549e531808e99f6511f41afda67cdd79b8063a0ad2273f3dee378d7c48d55e361acfa83c9d5de6a6be836d82f6d244a8f7959a5e918bcd3fdde570d2d9e9fc59f1b95a6bb71d81fee909250d40beca28441e35a2bc2ed1a383ea99ff4b39e373a5f422cb41d18bf6532e26010000a04631c26ad939e59622c29a76e966a43cae26d833c4a13e463ffb3bd9d9c37a278acee35be11a57bf6f0c033ac66907a46d841898c6fa98ef3f519b32e1db37c553e9177899773721e";
        var enc2: [256]u8 = undefined;
        const enc2_res = try fmt.hexToBytes(&enc2, check2);

        const dec2 = try rsa.decryptPkcs1v15(alloc, pri_key, enc2_res);
        defer alloc.free(dec2);

        try std.testing.expectEqualStrings(msg, dec2);
    }

    {
        const check2 = "301b1064b0ea6f8f3e4196459e5ccd0bfc77c61bdc62edb8c7287a5ae0944fde45374b8ff242916c0abf26df9bae70c933a37a89094753556f038c7d832bc755cb16f76e6e8c64b714f3efe584c76706123ffedd13926d79c2d6e6287ebc778cb1c4106cce481a654eda35e41a0a435291825cecfe9a3bff3c10a6b6108a1ad3c74e6b0a6129d980802ef47f5f96ef88863d629d7f57191da29a76d85a463cc9ee7f9df9efed535aea79a3da0ae38abb03712d65c6ebb4746c6396dc090f0ceb5b7ef989403a70e89768e52a4f08b7f3b205eefd1be4c45b6178756ca58858f9f1f8a06f5abe0cba640f3278656524872117f05159fb750b95a083c55e11207e";
        var sig2: [256]u8 = undefined;
        const sig2_res = try fmt.hexToBytes(&sig2, check2);

        try rsa.verifyPss(pub_key, sha2.Sha384, msg, sig2_res, .{
            .salt_leng = rsa.pss_salt_length_auto,
        });
    }

    {
        const check2 = "83c83ccf7d76b89bedacbb415e3a0ae219b1dc5b12ea80899e427d51c0594f35b41dedd20224b6e2e84710c78cb3583646de949423179c6b565da28edd139e042b1e2eb2f0b3220a6de904ce5c41e4e870123b29745ba9cdb2818882152ad1024c00d7a0e270846df027e31b687964b9323efd8238e473964106dbc0b3aac915dc3c7783abb721fd7a47de919633c7c4c2c6f8cd74c2fed2edcaf60236cff36457e1dc4e7a21ee8e7b4584e3cff4433d7d1e260a81e96ef6d8991c6b70ff5421f750a225a30167073e57c3c3d00d033ca4c97658c6f8cf82cf5732e2c634e41d521030c9be4798494004bacb5fe047897ee6effaf482bfc56b463bb369973f12";
        var enc2: [256]u8 = undefined;
        const enc2_res = try fmt.hexToBytes(&enc2, check2);

        const label = "label-test";

        const dec2 = try rsa.decryptOaep(alloc, pri_key, sha2.Sha384, enc2_res, label);
        defer alloc.free(dec2);

        try std.testing.expectEqualStrings(msg, dec2);
    }
}

test "Key check" {
    const alloc = testing.allocator;
    const io = testing.io;

    const random = utils.cryptoRand(io);

    const kp = try rsa.KeyPair.generate(alloc, random, 1024);
    const pri_key = kp.secret_key;
    const pub_key = kp.public_key;

    var secret_key = kp.secret_key;
    defer secret_key.deinit(alloc);

    {
        const pri_key2 = kp.secret_key;
        const pub_key2 = pri_key.public();

        try std.testing.expectEqual(true, pri_key2.equal(pri_key));
        try std.testing.expectEqual(true, pub_key2.equal(pub_key));
    }

    {
        const kp2 = try rsa.KeyPair.generate(alloc, random, 1024);

        var secret_key2 = kp2.secret_key;
        defer secret_key2.deinit(alloc);

        try std.testing.expectEqual(false, kp2.secret_key.equal(pri_key));
        try std.testing.expectEqual(false, kp2.public_key.equal(pub_key));
    }
}

fn test_publicKey_size() !void {
    const alloc = testing.allocator;
    const io = testing.io;

    const random = utils.cryptoRand(io);

    {
        const kp = try rsa.generate_key(alloc, random, 512);
        try std.testing.expectEqual(64, kp.public_key.size());

        var secret_key = kp.secret_key;
        defer secret_key.deinit(alloc);
    }

    {
        const kp = try rsa.generate_key(alloc, random, 1024);
        try std.testing.expectEqual(128, kp.public_key.size());

        var secret_key = kp.secret_key;
        defer secret_key.deinit(alloc);
    }

    {
        const kp = try rsa.generate_key(alloc, random, 2048);
        try std.testing.expectEqual(256, kp.public_key.size());

        var secret_key = kp.secret_key;
        defer secret_key.deinit(alloc);
    }

    {
        const kp = try rsa.generate_key(alloc, random, 4096);
        try std.testing.expectEqual(512, kp.public_key.size());

        var secret_key = kp.secret_key;
        defer secret_key.deinit(alloc);
    }
}

test "PublicKey size" {
    // try test_publicKey_size();
}

fn feFromHex(alloc: Allocator, n: rsa.Modulus, str: []const u8) !rsa.Fe {
    const bytes = try hexDecode(alloc, str);
    defer alloc.free(bytes);

    const out = try rsa.Fe.fromBytes(n, bytes, .big);
    return out;
}

test "SecretKey precompute from hex" {
    const alloc = testing.allocator;

    const nbytes = try hexDecode(alloc, "9d0f502cf5365bf3949f1bfaa444fa9c9fd0f9126e2d86a753f276e5d5ff813be4f33b88603a6e569b83a363cbb17e0e7c1dd86bc067b9955eec933e08ab75dba44b758a95439e327087d4d5e017c8f79da4d7c7d694ec397fbfeb04a7ee265af15407db70b840aacc03703dc74bf48707f00e781536bf971b61d38d5825838ebd4bed1db8b3f508e15e2e622839b3b0e1fe051b51b2834801df59131e11e7e8cf2120173f4254b9e5a3cab2dcb14f6d4abf087e58876b880eb1d488af21bf80e565939afd08a3ba046444180a955d1f19a40bb51ebcd2a4178df97ee9cf8f145d13d84eef37ea61577e65de80271a3dfc2fbbca2dc5f3ac867aa48c7477b767");
    const n = try rsa.Modulus.fromBytes(nbytes, .big);
    defer alloc.free(nbytes);

    const e = try feFromHex(alloc, n, "010001");
    const d = try feFromHex(alloc, n, "63d392db30747f975f948ddd0e4205a43d743e8b775a1a670a55673b087ca0f0a7c1edc9ed97d5ffd852a02c53109a95ac4feff9f4ce38c7f7109939e99ac98b746ebde3faa182d07e73e754955da8cfb1f44f6e66363bbb0436c0b331e58d9d6a1c45ee3543f75e57d3aba8a89edf6a602235a01fa3afbce49b9632159faa70b570ac22d54af63e1c2f09869d91a0a4cbe4f2f4f0ba6c7469df09a1a121b7044df20b0e90089ae1e4d194bd72c85ead2db6de51b69961b0454b2ed3ac0ed9c1cd75dac818a6cb2d47ec0d950907ad14d68812b4ec83766795369c81fa10eab57c9774bf83f2d9eebc5f96c58d0a864bf005b905cf26deda7c5220754e2ee2b9");
    const p = try feFromHex(alloc, n, "cc558bc7e22c34a9b5012f75ed39ccb284f2f4a64af78652b5cb6f77999202344161192ae63a5cd048d1943b80b98a66e15142187efc2d471f0f7d258843790d87b190a2a522a299b3b8ccf1d250b3003394d29ff6a9a79bbf9b08219d45969147dad74b44ad223adbebf48a2a0dd9ad394a8838fc8bbadc7025001663e4b46b");
    const q = try feFromHex(alloc, n, "c4c5b893ac7215a18383cba6b27bb4e0f8a7890649da0c26c317d1703c16ae7f875686002f840857d814d75ada28b7ac54e3b7a1db6af3a8b67b780beb90a32f80eebb839bdeecf309faca921dd00aeb359aa4b1b93c0357df1c52dcd992548f6739b243630a6149293f8480d38b6ce2b4d603dc5d9d21914a08e3cf020067f5");

    var primes = [_]rsa.Fe{ p, q };

    var prikey: rsa.SecretKey = .{
        .public_key = .{
            .n = n,
            .e = e,
        },
        .d = d,
        .primes = try alloc.dupe(rsa.Fe, primes[0..]),
    };

    try prikey.precompute(alloc);

    defer prikey.deinit(alloc);

    const dp = prikey.precomputed.?.dp;
    const dq = prikey.precomputed.?.dq;
    const qinv = prikey.precomputed.?.qinv;

    var dpbuf: [rsa.max_modulus_len]u8 = undefined;
    try dp.toBytes(&dpbuf, .big);
    const new_dpbuf = utils.stripLeadingZeros(&dpbuf);

    var dqbuf: [rsa.max_modulus_len]u8 = undefined;
    try dq.toBytes(&dqbuf, .big);
    const new_dqbuf = utils.stripLeadingZeros(&dqbuf);

    var qinvbuf: [rsa.max_modulus_len]u8 = undefined;
    try qinv.toBytes(&qinvbuf, .big);
    const new_qinvbuf = utils.stripLeadingZeros(&qinvbuf);

    try testing.expectFmt("8a869c63005453c791aca20e62ab42b8ec2501f312f3c81e9e9cb28ef48fe5eaa3403e9db4c37054cc69390335fb9376b7de2cdf0a87cff25d7e54ab733bbaff8f34b4076fc8914f7e66149b04a82d123fe5eefcff6e78f0bfef4c8ded5f55fa5c2a62b6e67231b8918bdf9723778c51417be3ea2e5c546c49a2ebf241fab4cd", "{x}", .{new_dpbuf});
    try testing.expectFmt("6fcd7c1b840eea5573f94d9c30ab7351a456e4d74adcf6ac8b8b1bf82e5c20d7db19015857a7286a691f2661bbb508ef84e8422d581383d067a6edc5b019e56e974e8e02b06cd0ab230f794bde5e97e59ef677ff77252f2d1d5ae58610a541209de13d75666fbe692863abb0db01cc635fa67e591663b26fefe5ef326e8bb685", "{x}", .{new_dqbuf});
    try testing.expectFmt("a3025ed7af8f1b9536f34fa9cd0f6e647b61bf31017926070b77565b5f2572d9c83003e307749f78a90e5b3bf15df64371ec82308ddf3a39c35501c816fb01ab21632152d71652cb43e2796b47dd29de4511371ec56e760f9d35c14e5e836db3b492866fc401ee59d0e8d64121a55695fc2ef495861c0ca2d42ff54ca622bcb0", "{x}", .{new_qinvbuf});

    try std.testing.expectEqual(0, prikey.precomputed.?.crt_values.len);
}

test "SecretKey precomputeLegacy crts" {
    const alloc = testing.allocator;

    const nbytes = try hexDecode(alloc, "9d0f502cf5365bf3949f1bfaa444fa9c9fd0f9126e2d86a753f276e5d5ff813be4f33b88603a6e569b83a363cbb17e0e7c1dd86bc067b9955eec933e08ab75dba44b758a95439e327087d4d5e017c8f79da4d7c7d694ec397fbfeb04a7ee265af15407db70b840aacc03703dc74bf48707f00e781536bf971b61d38d5825838ebd4bed1db8b3f508e15e2e622839b3b0e1fe051b51b2834801df59131e11e7e8cf2120173f4254b9e5a3cab2dcb14f6d4abf087e58876b880eb1d488af21bf80e565939afd08a3ba046444180a955d1f19a40bb51ebcd2a4178df97ee9cf8f145d13d84eef37ea61577e65de80271a3dfc2fbbca2dc5f3ac867aa48c7477b767");
    const n = try rsa.Modulus.fromBytes(nbytes, .big);
    defer alloc.free(nbytes);

    const e = try feFromHex(alloc, n, "010001");
    const d = try feFromHex(alloc, n, "63d392db30747f975f948ddd0e4205a43d743e8b775a1a670a55673b087ca0f0a7c1edc9ed97d5ffd852a02c53109a95ac4feff9f4ce38c7f7109939e99ac98b746ebde3faa182d07e73e754955da8cfb1f44f6e66363bbb0436c0b331e58d9d6a1c45ee3543f75e57d3aba8a89edf6a602235a01fa3afbce49b9632159faa70b570ac22d54af63e1c2f09869d91a0a4cbe4f2f4f0ba6c7469df09a1a121b7044df20b0e90089ae1e4d194bd72c85ead2db6de51b69961b0454b2ed3ac0ed9c1cd75dac818a6cb2d47ec0d950907ad14d68812b4ec83766795369c81fa10eab57c9774bf83f2d9eebc5f96c58d0a864bf005b905cf26deda7c5220754e2ee2b9");
    const p = try feFromHex(alloc, n, "cc558bc7e22c34a9b5012f75ed39ccb284f2f4a64af78652b5cb6f77999202344161192ae63a5cd048d1943b80b98a66e15142187efc2d471f0f7d258843790d87b190a2a522a299b3b8ccf1d250b3003394d29ff6a9a79bbf9b08219d45969147dad74b44ad223adbebf48a2a0dd9ad394a8838fc8bbadc7025001663e4b46b");
    const q = try feFromHex(alloc, n, "c4c5b893ac7215a18383cba6b27bb4e0f8a7890649da0c26c317d1703c16ae7f875686002f840857d814d75ada28b7ac54e3b7a1db6af3a8b67b780beb90a32f80eebb839bdeecf309faca921dd00aeb359aa4b1b93c0357df1c52dcd992548f6739b243630a6149293f8480d38b6ce2b4d603dc5d9d21914a08e3cf020067f5");

    const c1 = try feFromHex(alloc, n, "c4c5b893ac7215a18383cba6b27bb4e0f8a7890647da0c26c317d1703c16ae7f875686002f840857d814d75ada28b7ac54e3b7a1db6af3a8b67b780beb90a32f80eebb839bdeecf309faca921dd00aeb359aa4b1b93c0357df1c52dcd992548f6739b243630a6149293f8480d38b6ce2b4d603dc5d9d21914a08e3cf020067f5");
    const c2 = try feFromHex(alloc, n, "c4c5b893ac7215a18383cba6b27bb4e0f8a7890647da0c26c317d1703c16ae7f875686002f840857d814d75ada28b7ac54e3b7a1db6af3a8b67b780beb90a32f80eebb839bdeecf309faca921dd00aeb359aa4b1b93c0357df1c52dcd992548f6739b243630a6149293f8480d38b6ce2b4d603dc5d9d21914a08e3cf020067f8");

    var primes = [_]rsa.Fe{ p, q, c1, c2 };

    var prikey: rsa.SecretKey = .{
        .public_key = .{
            .n = n,
            .e = e,
        },
        .d = d,
        .primes = try alloc.dupe(rsa.Fe, primes[0..]),
    };

    try prikey.precompute(alloc);

    defer prikey.deinit(alloc);

    const dp = prikey.precomputed.?.dp;
    const dq = prikey.precomputed.?.dq;
    const qinv = prikey.precomputed.?.qinv;

    var dpbuf: [rsa.max_modulus_len]u8 = undefined;
    try dp.toBytes(&dpbuf, .big);
    const new_dpbuf = utils.stripLeadingZeros(&dpbuf);

    var dqbuf: [rsa.max_modulus_len]u8 = undefined;
    try dq.toBytes(&dqbuf, .big);
    const new_dqbuf = utils.stripLeadingZeros(&dqbuf);

    var qinvbuf: [rsa.max_modulus_len]u8 = undefined;
    try qinv.toBytes(&qinvbuf, .big);
    const new_qinvbuf = utils.stripLeadingZeros(&qinvbuf);

    try testing.expectFmt("8a869c63005453c791aca20e62ab42b8ec2501f312f3c81e9e9cb28ef48fe5eaa3403e9db4c37054cc69390335fb9376b7de2cdf0a87cff25d7e54ab733bbaff8f34b4076fc8914f7e66149b04a82d123fe5eefcff6e78f0bfef4c8ded5f55fa5c2a62b6e67231b8918bdf9723778c51417be3ea2e5c546c49a2ebf241fab4cd", "{x}", .{new_dpbuf});
    try testing.expectFmt("6fcd7c1b840eea5573f94d9c30ab7351a456e4d74adcf6ac8b8b1bf82e5c20d7db19015857a7286a691f2661bbb508ef84e8422d581383d067a6edc5b019e56e974e8e02b06cd0ab230f794bde5e97e59ef677ff77252f2d1d5ae58610a541209de13d75666fbe692863abb0db01cc635fa67e591663b26fefe5ef326e8bb685", "{x}", .{new_dqbuf});
    try testing.expectFmt("a3025ed7af8f1b9536f34fa9cd0f6e647b61bf31017926070b77565b5f2572d9c83003e307749f78a90e5b3bf15df64371ec82308ddf3a39c35501c816fb01ab21632152d71652cb43e2796b47dd29de4511371ec56e760f9d35c14e5e836db3b492866fc401ee59d0e8d64121a55695fc2ef495861c0ca2d42ff54ca622bcb0", "{x}", .{new_qinvbuf});

    try std.testing.expectEqual(2, prikey.precomputed.?.crt_values.len);

    {
        const crt = prikey.precomputed.?.crt_values[0];

        var exp_buf: [rsa.max_modulus_len]u8 = undefined;
        try crt.exp.toBytes(&exp_buf, .big);
        const new_exp_buf = utils.stripLeadingZeros(&exp_buf);

        var coeff_buf: [rsa.max_modulus_len]u8 = undefined;
        try crt.coeff.toBytes(&coeff_buf, .big);
        const new_coeff_buf = utils.stripLeadingZeros(&coeff_buf);

        var r_buf: [rsa.max_modulus_len]u8 = undefined;
        try crt.r.toBytes(&r_buf, .big);
        const new_r_buf = utils.stripLeadingZeros(&r_buf);

        try testing.expectFmt("72947fe11cb8f4d7a3a6693b74cd27747e00221eaa2413e44340e7c1906ce71367e644be9e2d7bc9d9aa25da168a4ce7b7ad3cf45d39abbab55571da1d11634a2c645fa6038b61822b037a02e76bcdbfc8c497b47b863b485b270b46c520262204e8f000873e95efee8a9235b7a628feef36feb93adba8d882f0a0060ee95b19", "{x}", .{new_exp_buf});
        try testing.expectFmt("24866ea0c2869d06893e642a5f1f39a5b4cb050bd69dae13387bb7c2aa56344fc527708de0cad92eaa2e22f5f1c2fc7049e2d3cfa65dabea73c9fc2dac9fb2e3d72bff9030b2ae0b0cc7664478a9adb3bf05b106f9c586dbdd996006a15a58e69950c17f264d43984bf1c62f988554dcfaf736e53db4f921779dca67c95eabd6", "{x}", .{new_coeff_buf});
        try testing.expectFmt("9d0f502cf5365bf3949f1bfaa444fa9c9fd0f9126e2d86a753f276e5d5ff813be4f33b88603a6e569b83a363cbb17e0e7c1dd86bc067b9955eec933e08ab75dba44b758a95439e327087d4d5e017c8f79da4d7c7d694ec397fbfeb04a7ee265af15407db70b840aacc03703dc74bf48707f00e781536bf971b61d38d5825838ebd4bed1db8b3f508e15e2e622839b3b0e1fe051b51b2834801df59131e11e7e8cf2120173f4254b9e5a3cab2dcb14f6d4abf087e58876b880eb1d488af21bf80e565939afd08a3ba046444180a955d1f19a40bb51ebcd2a4178df97ee9cf8f145d13d84eef37ea61577e65de80271a3dfc2fbbca2dc5f3ac867aa48c7477b767", "{x}", .{new_r_buf});
    }

    {
        const crt = prikey.precomputed.?.crt_values[1];

        var exp_buf: [rsa.max_modulus_len]u8 = undefined;
        try crt.exp.toBytes(&exp_buf, .big);
        const new_exp_buf = utils.stripLeadingZeros(&exp_buf);

        var coeff_buf: [rsa.max_modulus_len]u8 = undefined;
        try crt.coeff.toBytes(&coeff_buf, .big);
        const new_coeff_buf = utils.stripLeadingZeros(&coeff_buf);

        var r_buf: [rsa.max_modulus_len]u8 = undefined;
        try crt.r.toBytes(&r_buf, .big);
        const new_r_buf = utils.stripLeadingZeros(&r_buf);

        try testing.expectFmt("7680dbd54fc851285c0ee3834e88a4e37865d19a3d82ac12f9338147c190b6af4ccb3b8f72cdbb93f3adeb8af464ed7bb1638bd4349dc96dc4295d164287608b0870fae8308b7cb6c22109cc60dcbb31be76ce23ac22e4a44f9eacab6c3f83cfdee50a980f9ee8094e5e43336305191494fd029ee1774c7a47b6b7ed3656bcef", "{x}", .{new_exp_buf});
        try testing.expectFmt("5512624023ed5ef4f7b4a4f2c159a73075a6e45cf56dabfe654b7e65b7c701e1a9119d7a0fd285f79072f838be82285c7076802ff5f1817ae1a1905d0920c48905db7e4212d51745ce775b48558adea4e1a13cd41aba042a8af3942e3265e93ccb72ec55074d75afa30cadf5ddedf74c57d38254e813895af3b0f82f2f699f3b", "{x}", .{new_coeff_buf});
        try testing.expectFmt("78b90768b98df340623395bbdaaacf866f405b94e51b8a53f1586d576ef603bd97bb07ca8e439ffbf9b2276acce1985c12224f7b31041b880fc0a9fe0ddb076feb0139056cd82af5a5c5eb13630976f94486d5e0c51021ba4ecfddf58d972911164659610639bb0ad1c7acd138802ca1fbd0ecd3f8892bdaddf4efb2735f19d4b3903ed1767ba94e719e46b9794a484f16386e76bfb9802a28bc63e6dd1ed6c60f86c993d10a81e9fbcc7631501e32a0348049000b76d176b8efc250b3bb2828ec5adcd92fec125837a9c30811aa7cadc57eeacc51c82e67d4ea1d45efd97aaed198c23c123fd2ec067c98fafa034c3fd1eb1f879fc1bc06c26c1dbf110d18593afc32238db74f01f6e66d132517bff2178f14ff58ffe54bab1e020e99efe61c48f06ac1583cbc5cd1a8e95a817319f785d290674ddba2c57cd1c58c36192f8dfdc2e3ee94171fc494176d1a0de940c235ea4c3ae5dfaaad838591016088c666e82a5e88a4b65a75cb01e96a176b70054e40531653499371fa228dff6f5cf693", "{x}", .{new_r_buf});
    }
}

fn TestRNG(io: std.Io) type {
    return struct {
        pub fn fill(_: *anyopaque, buffer: []u8) void {
            io.random(buffer);
        }
    };
}

fn getIoRand(io: std.Io) std.Random {
    const test_rng: std.Random = .{
        .ptr = undefined,
        .fillFn = TestRNG(io).fill,
    };

    return test_rng;
}

test "KeyPair generateMultiPrimeKey" {
    const alloc = testing.allocator;

    var prng = std.Random.DefaultPrng.init(0xC0FFEE_1234_5678);
    const random = prng.random();

    const kp = try rsa.KeyPair.generateMultiPrimeKey(alloc, random, 1024, 4);

    var secret_key = kp.secret_key;
    defer secret_key.deinit(alloc);

    const msg = "rsa PSS signature";

    var sig = rsa.Pss(TestHash).Signer.init(alloc, random, kp.secret_key, .{});
    sig.update(msg);
    const signed = try sig.finalize();

    const signed_bytes = signed.toBytes();
    try testing.expectEqual(true, signed_bytes.len > 0);

    defer alloc.free(signed_bytes);

    try signed.verify(msg, kp.public_key, .{});
}

test "SecretKey generateMultiPrimeKey" {
    const alloc = testing.allocator;
    const io = testing.io;

    const random = utils.cryptoRand(io);

    const kp = try rsa.generateMultiPrimeKey(alloc, random, 1024, 4);

    var secret_key = kp.secret_key;
    defer secret_key.deinit(alloc);

    const prikey = kp.secret_key;
    var pubkey = kp.public_key;
    try pubkey.check();

    try std.testing.expectEqual(4, prikey.primes.len);

    var crt2_buf: [rsa.max_modulus_len]u8 = undefined;
    try prikey.primes[3].toBytes(&crt2_buf, .big);
    const new_crt2_buf = utils.stripLeadingZeros(&crt2_buf);

    try std.testing.expectEqual(true, new_crt2_buf.len > 0);
    // try testing.expectFmt("ecdcc6259721c1adb5af2642e081877d99a27157157c09051857fcfdd56dfa61", "{x}", .{new_crt2_buf});
}

test "SecretKey precomputeLegacy crts from der" {
    const alloc = testing.allocator;

    const prikey_str = "MIIJxgIBAQKCAgEA4tz4nbwZOmAiBRMXRyM36jBRVObxWCRLX3OOxmTQqV3P+LgIesYTKBXJqOorPQFy1hT4aIj73PKW+vrhTKs1zn+OnNctuUMADkxTNtq9uER1S5X6rBs29q9zuwwF1Vx95DT1wwfzUiEMy0E1shrG2zbLxSP/hhjwQ9uiSu9QPOLI1C2w3TV83mOuCU9bH9p85u8SRG+z9ci1tiGmGpk7bPBbwmAoB+kI1K5S+X86ZNSEiStdG4tDGLNqjpG6hROIzDSio+toYiCrKk64/hZZY+l8R0dotJr/GLcfyNkH9XD0MXfz7WsPLsNCiEVBryU+pskP3PQtEHqFX/XqRu56iVA4S44uzy+mldDrQKb3R5LzZ9Afc+dYWD2SI8anoDEAJ/mg/UzRQt+cn/bghV9lPVNce45pKhjz5bcanTMer8nKS5s/a2PsxGLkTlUKY03Ie/mCtZFnRUoSnWhttBBiSy92OXwPkcUSoYksqHdmoHyaTbZsyxLy52Ug2nFL/ZbPafZrvMu1shE8hYTBi45mx8XOYvfgVAwteTG1X8o7AIkv60oiF4hNaqFY+sfzJmics6VilpduufTS1cfP/spoKFEq/tgUMTG2j0irM7hcfwQwH6Z51XGVVvlZI2aiXpcDfVOqIobmvXbbufe+WYMzuILrBp0G/y5ofN3YOl/XIYUCAwEAAQKCAgAxWT/7j98tA5xi3jRCFTckij4m6dW2Bq8epFR6c5OwQ+fpgp7VliC0p4imZcniC16fkxA2LRYcieitz8USmGur77NmCqi3lAt/ELtJQ2vhmYKqXoWYypK6NpBGL+dU8jmwWpTbR+91/hp6XEUB6TE4nkLVL292DBa3rB8xjb02gJLvI48T50tDE0RhhaULQtNcj1b5sWreKLgdVr4wUuYd87YYgSP0hzEW/FkiUVqIN4HtZrgjrCssxXnHBmIzXddfsjZVpUL3L54rK8Sq0CS/PiSAKrbh77Y+6Q9YVWr432+bDS/nE5Zt2IAhgx492jqoJf6hS1c+69KjFsZJAc4RaGslUBaxowKy9lmiz1JLpMonWM0qn3XXVz90F6NCJ0HZzh+ZAkbpN8/KO80wePR5pSQvwBaLPEO3mfydrBPd64TVl+B/mNDHBFwmofUpc7pUY4FBGlXTyUvIxcorz7IsjUD9BxDtSh2+PMue5LJQVGGz7LBeaBmQYi0DnUtURAs5CpMAWhOIuwSO9RyOQ7b1//T4DVoeDCA6/J9QpEQrAP25CXJNFFtMbjki4V2ekF5Gx7flighV9RLgY8QH1jNRjrluByyANt85f1nNxugdxhkDYJ084uHqRU4kVgjsuhnkmUhsWgtMoRFLg2oHV8ARHVY5QCfm7+oom2H/GUEAAQKBgQD9Y4cUUBg5JqE2Li3kVoUci0R9oZ4uquiO0lDEnDnK11w+jot6EoZMFfGPqa1uq6UszlBnf20Pg+zkBbsuBvRqfQonhYPf91Y7fnno6HKEKyrqFF/6ucgBNZYPoDk6guWEJBWG3/3Zhw1BkMRsxJ5EbL33AS7/2WZSkMorjeEHawKBgQDnZ7SuDqvqk8qSaKnko7UJz2BunNt71uZPDDDzaapYeQAscamEdzVxCEEnwFXTB8s45agB/uLVVXm6/uPbvFuX3y0mRisJqxb1TZ9Zkj6BpDsNkT9Eio56zaX9JdDTmCgRakS70Kc91YM+8MvNFSepQWZQKYYsG+vBGcIZB4tLbQKBgQDjnZ8+4QARfqD8YZk573qdfIEm9aJ5u28ytLx3EPtdOf4T98pU+wUGngOjkMFJlAjJaf+SKUZX1KNc5cUSAI9YhUA05lvjOXSN9vwd+4i7L2faZDkfqfl/FJrbKIugAuuXuy5XPSj0WbvPtPKt3iVpw+EVXEvS6oBfFM93Nnj5RwKBgQCTdv8pPKhJ4Mzi6Ff8IGcqTUFCvCsSjCxQi5BWTiwEHXgC2pwQknc4BO6gim0nAnx7Ub7zJp8fHE1q4SwLx8kGy25WSbj7fFAxGrpFtnCm5SXMy5bp8vJBR/RTklm1ve0qy/HpTlqFiR8OaR03IBgaQFcXFp8uVMy0TdnnYWtfMQKBgQD783N87lhtWsGUCLMmJ/EPHu2Dc9Vl25W5omy5LKUulMJFL+5v6y5tqeS2qRvyJIZdgFflHnbo7tkO4CJIUmM4wpC/I9ffZw7U71vw5U+uA9GlXiSB0U/7pluXfI/GAifeM/wefxYxibYH9pL/aNkkuQB01lI3ITT8IGP1u1j60DCCAx0wggGLAoGBAP856mQvpOcRXeFCS6h/LyYk1Kf+FYIccYtrYiEfVhzd3AZGYky136vG8PtMRNy1w+ceZKCla9uTP3WaTp6kO9iNt8Y3M2038dfsrcvrp/ObPuY4hLGKUYxpJfcQU2HTnwjona0IlYI6ojzJfomj12jK0b8MzXEdCkRzrT8K0cOrAoGBALCrMWGaTUaZkeeckWyYZVW9BusmiVLgR4Sfl3SgEWa3+Fbrn53EA4kPk74QBFbXBz1Tn4pIF4oNuk64upU70CVNrBlsGpAOuryhm4hdnouVOgv4sXmH6n0MR/hmd6Fu8FYlVwfwujVESwtS2uGB5Vknk9rwjMEwveu2OwU5gwwzAoGARlroMNglECCLjQkfUY9/TmRORbsuS5sBXyZ9dfSbhtwPvmVdkAmQnUODrhlu3sDiWKsNEPcWRGxPtDgjXCDudgV4lInKtQ6LL3qZA5nBg7CRXWbcN3HOBuGJAnm7b6y022/osrIvWNK6Q2EKxXgL2Lx7LJSDtupL7zBrx7FBZrQwggGKAoGBAP5UlPte6Opn/JUsLheRv9ZnVvVGx4o8B47s7Urtp/WuahgPf4pmkqfEqhZCWnioqmJr1hjVG+l18+PQARyUd3s8WtVnF/Nsm0ZBEn+/6bq/azrTZu8jvArFfYwEYQE7iD4XiGpLVqsKMP1Fap0idFEK4/Z8v7xlo7r89jSV7yIBAoGAKiz0l8rhbR3ZcRNmgVoWKgPxE7OtG2thBX6cyzQmCkPmLB9F0zm3UEL4wcA3KJMvzip70ppkio6Y50pzJL4qIjGcDo+OFTwJc9kOrEizBdkAezzbcQTIBjFB5JpFS+MHcOSOJrJfqPWDsjx0taIlD9tyekmtshxYzoVsfsPuaAECgYAoiLXjyxIfwRLq8llMgQ+JwNX5JB8ZFA4gUEPMUxc70Rc7HX47GEdrl4731S1i/5kwq6hpypP3VVHMOIsdlXMc9bdAhFPlI6zCF6NJtt3fDi4BmJBfU9AykCwojlwu7GyKpeFzeIcfUMTvmimYvvu3d3ni5KFV7SEsFcPwusoU1g==";
    const prikey_bytes = try base64Decode(alloc, prikey_str);
    defer alloc.free(prikey_bytes);

    var prikey = try rsa.SecretKey.fromDer(alloc, prikey_bytes);
    defer prikey.deinit(alloc);

    try prikey.precompute(alloc);

    const dp = prikey.precomputed.?.dp;
    const dq = prikey.precomputed.?.dq;
    const qinv = prikey.precomputed.?.qinv;

    var dpbuf: [rsa.max_modulus_len]u8 = undefined;
    try dp.toBytes(&dpbuf, .big);
    const new_dpbuf = utils.stripLeadingZeros(&dpbuf);

    var dqbuf: [rsa.max_modulus_len]u8 = undefined;
    try dq.toBytes(&dqbuf, .big);
    const new_dqbuf = utils.stripLeadingZeros(&dqbuf);

    var qinvbuf: [rsa.max_modulus_len]u8 = undefined;
    try qinv.toBytes(&qinvbuf, .big);
    const new_qinvbuf = utils.stripLeadingZeros(&qinvbuf);

    try testing.expectFmt("e39d9f3ee100117ea0fc619939ef7a9d7c8126f5a279bb6f32b4bc7710fb5d39fe13f7ca54fb05069e03a390c1499408c969ff92294657d4a35ce5c512008f58854034e65be339748df6fc1dfb88bb2f67da64391fa9f97f149adb288ba002eb97bb2e573d28f459bbcfb4f2adde2569c3e1155c4bd2ea805f14cf773678f947", "{x}", .{new_dpbuf});
    try testing.expectFmt("9376ff293ca849e0cce2e857fc20672a4d4142bc2b128c2c508b90564e2c041d7802da9c1092773804eea08a6d27027c7b51bef3269f1f1c4d6ae12c0bc7c906cb6e5649b8fb7c50311aba45b670a6e525cccb96e9f2f24147f4539259b5bded2acbf1e94e5a85891f0e691d3720181a405717169f2e54ccb44dd9e7616b5f31", "{x}", .{new_dqbuf});
    try testing.expectFmt("fbf3737cee586d5ac19408b32627f10f1eed8373d565db95b9a26cb92ca52e94c2452fee6feb2e6da9e4b6a91bf224865d8057e51e76e8eed90ee02248526338c290bf23d7df670ed4ef5bf0e54fae03d1a55e2481d14ffba65b977c8fc60227de33fc1e7f163189b607f692ff68d924b90074d652372134fc2063f5bb58fad0", "{x}", .{new_qinvbuf});

    try std.testing.expectEqual(2, prikey.precomputed.?.crt_values.len);

    {
        const crt = prikey.precomputed.?.crt_values[0];

        var exp_buf: [rsa.max_modulus_len]u8 = undefined;
        try crt.exp.toBytes(&exp_buf, .big);
        const new_exp_buf = utils.stripLeadingZeros(&exp_buf);

        var coeff_buf: [rsa.max_modulus_len]u8 = undefined;
        try crt.coeff.toBytes(&coeff_buf, .big);
        const new_coeff_buf = utils.stripLeadingZeros(&coeff_buf);

        var r_buf: [rsa.max_modulus_len]u8 = undefined;
        try crt.r.toBytes(&r_buf, .big);
        const new_r_buf = utils.stripLeadingZeros(&r_buf);

        try testing.expectFmt("b0ab31619a4d469991e79c916c986555bd06eb268952e047849f9774a01166b7f856eb9f9dc403890f93be100456d7073d539f8a48178a0dba4eb8ba953bd0254dac196c1a900ebabca19b885d9e8b953a0bf8b17987ea7d0c47f86677a16ef056255707f0ba35444b0b52dae181e5592793daf08cc130bdebb63b0539830c33", "{x}", .{new_exp_buf});
        try testing.expectFmt("465ae830d82510208b8d091f518f7f4e644e45bb2e4b9b015f267d75f49b86dc0fbe655d9009909d4383ae196edec0e258ab0d10f716446c4fb438235c20ee7605789489cab50e8b2f7a990399c183b0915d66dc3771ce06e1890279bb6facb4db6fe8b2b22f58d2ba43610ac5780bd8bc7b2c9483b6ea4bef306bc7b14166b4", "{x}", .{new_coeff_buf});
        try testing.expectFmt("e50b74c4f097c87debbc2a33bd3d44a5c3fed269b24f4ef32a9e7936645b807366ff691b7be95e8b3340f3cf90f9a93e825a8d16afd0763898b847b3cccf20c95791ce021c52c65e4a9321b4712bd94d22f8830971de54618f1ad010124b5c063fb15303b5178e9dd5ad1ad43f07118df3e5405a4aca9691f16fc29f8578ad885abe16d0aa9bbd78d46aa8418c3205380f98a6b5e39f3dbc33108477733ef8981990b6f6a5f33218b35529f76fe0414991f5b11532ddb3d108e5148dc14504ecd7d475adec6f76d844dcc686fcf459beb1bf8076d8eaf6b0fbada3b90a714073ba4b447c87816a148c853714ae4b5b58ba2000e56dbfae765073d6f24a15818f", "{x}", .{new_r_buf});
    }

    {
        const crt = prikey.precomputed.?.crt_values[1];

        var exp_buf: [rsa.max_modulus_len]u8 = undefined;
        try crt.exp.toBytes(&exp_buf, .big);
        const new_exp_buf = utils.stripLeadingZeros(&exp_buf);

        var coeff_buf: [rsa.max_modulus_len]u8 = undefined;
        try crt.coeff.toBytes(&coeff_buf, .big);
        const new_coeff_buf = utils.stripLeadingZeros(&coeff_buf);

        var r_buf: [rsa.max_modulus_len]u8 = undefined;
        try crt.r.toBytes(&r_buf, .big);
        const new_r_buf = utils.stripLeadingZeros(&r_buf);

        try testing.expectFmt("2a2cf497cae16d1dd9711366815a162a03f113b3ad1b6b61057e9ccb34260a43e62c1f45d339b75042f8c1c03728932fce2a7bd29a648a8e98e74a7324be2a22319c0e8f8e153c0973d90eac48b305d9007b3cdb7104c8063141e49a454be30770e48e26b25fa8f583b23c74b5a2250fdb727a49adb21c58ce856c7ec3ee6801", "{x}", .{new_exp_buf});
        try testing.expectFmt("2888b5e3cb121fc112eaf2594c810f89c0d5f9241f19140e205043cc53173bd1173b1d7e3b18476b978ef7d52d62ff9930aba869ca93f75551cc388b1d95731cf5b7408453e523acc217a349b6dddf0e2e0198905f53d032902c288e5c2eec6c8aa5e17378871f50c4ef9a2998befbb77779e2e4a155ed212c15c3f0baca14d6", "{x}", .{new_coeff_buf});
        try testing.expectFmt("e45a3a93475707dda0dc7e9f53bf5609486ed92537a6d825132de0c87d12574135f2c6bb3472d7989841181fd752f13e02c39be1124b4326f5bb53484a60b08e805db642f6419fb9e4d64fd2361aad024a128188bacdf4d4521cc1674b92454fe43c2c762713cda6325afc388ce7b4de40e0a37edbd8638f3320a749570ed2099c8353ac28043bb5b35388f132972f5f43cda9a4eb07af4a35a5fbc8b74794f25ffdcd02b0f67868d87a7bc39e7b7b0846206b1b3f004a31caff4756775a1e1096a38368dd01f3ebeb16f926f1b64656f835ed0fae784a8ebf97a7ba50850ee7c04089e70605a80c8c9a388be442d5772b110f07c08f22be823fc1943c519b508559c9a2e7c4ff838e37f5cc30a9cbebdaf8b85934431bd07bfb8832a7be446f9ebea8b0d43bfbc0e6b2f3d47a680c6f1cee7c73ff39ba03e1ce76cacea6d99548ad65e340cf405b72f2c083a488d38a45796b2c95a38c0d0035ce19b77d570fe179759739ce2e1c31425e6a6fe1cec907cec6926595bfa1dfe3fa1539cc7785", "{x}", .{new_r_buf});
    }
}

test "isProbablePrimes" {
    const alloc = testing.allocator;

    {
        const str_hex = "fd63871450183926a1362e2de456851c8b447da19e2eaae88ed250c49c39cad75c3e8e8b7a12864c15f18fa9ad6eaba52cce50677f6d0f83ece405bb2e06f46a7d0a278583dff7563b7e79e8e872842b2aea145ffab9c80135960fa0393a82e584241586dffdd9870d4190c46cc49e446cbdf7012effd9665290ca2b8de1076b";
        const bytes = try hexDecode(alloc, str_hex);
        defer alloc.free(bytes);

        const p = try rsa.Modulus.fromBytes(bytes, .big);
        const res = try utils.isProbablePrimes(p);
        try testing.expectEqual(true, res);
    }

    {
        const str_hex = "e767b4ae0eabea93ca9268a9e4a3b509cf606e9cdb7bd6e64f0c30f369aa5879002c71a984773571084127c055d307cb38e5a801fee2d55579bafee3dbbc5b97df2d26462b09ab16f54d9f59923e81a43b0d913f448a8e7acda5fd25d0d39828116a44bbd0a73dd5833ef0cbcd1527a941665029862c1bebc119c219078b4b6d";
        const bytes = try hexDecode(alloc, str_hex);
        defer alloc.free(bytes);

        const p = try rsa.Modulus.fromBytes(bytes, .big);
        const res = try utils.isProbablePrimes(p);
        try testing.expectEqual(true, res);
    }

    {
        const str_hex = "e767b4ae0eabea93ca9268a9e4b3b509cf606e9cdb7bd6e64f0c30f369aa5879002c71a984773571084127c055d307cb38e5a801fee2d55579bafee3dbbc5b97df2d26462b09ab16f54d9f59923e81a43b0d913f448a8e7acda5fd25d0d39828116a44bbd0a73dd5833ef0cbcd1527a941665029862c1bebc119c219078b4b6d";
        const bytes = try hexDecode(alloc, str_hex);
        defer alloc.free(bytes);

        const p = try rsa.Modulus.fromBytes(bytes, .big);
        const res = try utils.isProbablePrimes(p);
        try testing.expectEqual(false, res);
    }
}

test "randPrime" {
    const testRun = false;

    if (testRun) {
        const io = testing.io;

        const random: std.Random = .{
            .ptr = undefined,
            .fillFn = TestRNG(io).fill,
        };

        var primeBuf: [utils.max_modulus_len]u8 = undefined;
        const todo = 1024;
        const nprimes = 2;
        const i = 0;

        const primCount = todo / (nprimes - i);
        const primeLen = utils.byteLen(primCount);

        const primeBytes = primeBuf[0..primeLen];
        try utils.randPrime(random, primCount, primeBytes);

        try std.testing.expectEqual(true, primeBytes.len > 0);
    }
}

test "sign Prehashed with pkcs8 key" {
    const alloc = testing.allocator;
    const io = testing.io;

    const random = utils.cryptoRand(io);

    const prikey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDh/nCDmXaEqxN416b9XjV8acmbqA52uPzKbesWQRT/BPxEO2dKAURk5CkcSBDskvfzFR9TRjeDppjD1BPSEnuYKnP0SvmotoxcnBnHMfMBqGV8DSJyppu8k4y9C3MPq5C/rA8TJm0NNaJCL0BfAGkeyw+elgYifbRlm42VfYGsKVyIeEI9Qghk5Cf8yapMPfWNLKOhChXsyGExMBMonHZeseFH7UNwonNAFJMAaelhVqqmwBFqn6fBGKmvedRO7HIaiEFNKaMna6xJ5Bccjds4MhF7UC5PIdx4Bt7CfxvjrbIRYoBF2l30CNBblIhU992zPkHoaVhDkt1gq3OdO7LvAgMBAAECggEBALCJrWTv7ahnZ3efpqAIBuogTVBd8KaHjVmokds5jehFAbdfXClwYfgaT477MNVNXYmzN1w63sTl0DIxqiYRMCFHEHuGUg6cQ3tYqb50Y2spG9XTANTlF4UxEeDfX8ue7xz7kG8aNlf6TL084iEUVgmrAJGWikZJQjGZWPmtKC3OTeJY5Bev5qHVuMRe+XEM5aQc3ph+lXlOF0Qp0Eg8YRWprrev2faH6prMqu2JGomoac6sfM4QJhtEViF7Gw0XPthPTbF19IefuAwi9psMM/9CnQ+MTWN2i6IxoUdicsFuC+Wdlb3K5V/+uldNSr+ePEhcya+YTLK9IOcVwWKQHykCgYEA8XvuEribf+t0ZPtfxr+DC9nZHXbVoFx0/ARpSG+P/fp3Hn3rO9iYQ6OtZ9mEXTzf+dhYTaRWq6PbCOz6i0It+J8QSBdxU9OcQ4871mDe41IvSc1CCGMW4PeIYtNQEK0zrqhN7SMtKyUd7yAsYRCrIzMc7NjE2qJvFw5kh7xC3Q0CgYEA75Qjn5daNYSAOa/ILdOs5J/8oIaO27RNK/fSKm/btsMsyum8+YP/mWmm1MXBzG9WEKzZv5yEKOWCEVJYVsFQsGt9yLYW2WIKU5UxiuU0F1RImF/dphIbYOh7oGC3WfYKk2f+K7ftjc196ZkEkDuE2Xh1h75/67Mzztx1DbXj6OsCgYBcDRfFfyWXb5Og4smxo1M680H2H1RzmorlfnD7sbs733wE3Y8L8xanwf7Z9WqleA0Q2k1e22RGbWGTV3JyHzoS6d90+6qxf5qzjigLIkYUdUGdambfd5ZDD1ioA1Ej6kInM/TwjlYreiyc+LCyF36FHnjKOB9iEEU0jsH3k+YRCQKBgHMVLPuHX6zfhhyvxK/Gw4FbHKYbnNoKxRs+wvThoKAtJwIdv0n4TzppVttUV2CVhrkh3sM9MvrWLGGXtZmO6Oyl5dkZJuarQpydyRuYOCqQsQKI4lbY0c/+PQxwCQMsvi3KwXxMsM7yC+6/M0L5ZDp2s7ZOGvKktVlD6vJ4Eg+bAoGARnGGprSBW8dAb/s53r0paPh4k/bySrXdGEprLwk6g3S8+aylcmjUdjcIq4dEb4A/nv12dx1Sc4y99c62R0zi+TT6FYBIFDMz3HNVzO0Jr6SgC6CNVotL0D725CioR5U1NyTHHRLZth69HLuEZCZQlPJCbePXMRRHmOl1svzcVuo=";
    const pubkey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";

    const prikey_bytes = try base64Decode(alloc, prikey);
    const pubkey_bytes = try base64Decode(alloc, pubkey);

    defer alloc.free(prikey_bytes);
    defer alloc.free(pubkey_bytes);

    var pri_key = try rsa.SecretKey.fromPKCS8Der(alloc, prikey_bytes);
    const pub_key = try rsa.PublicKey.fromPKCS8Der(pubkey_bytes);

    defer pri_key.deinit(alloc);

    const msg = "rsa PSS signature";

    var h_msg: [TestHash.digest_length]u8 = undefined;

    var h = TestHash.init(.{});
    h.update(msg[0..]);
    h.final(h_msg[0..]);

    {
        var kp = try rsa.KeyPair.fromSecretKey(pri_key);
        var sig = try kp.signPssPrehashed(alloc, random, TestHash, h_msg, .{});

        const signed_bytes = sig.toBytes();
        try testing.expectEqual(true, signed_bytes.len > 0);

        defer alloc.free(signed_bytes);

        var veri = rsa.Pss(TestHash).Signature.fromBytes(signed_bytes);
        try veri.verifyPrehashed(h_msg, pub_key, .{});
    }

    {
        var kp = try rsa.KeyPair.fromSecretKey(pri_key);
        var sig = try kp.signPkcs1v15Prehashed(alloc, TestHash, h_msg);

        const signed_bytes = sig.toBytes();
        try testing.expectEqual(true, signed_bytes.len > 0);

        defer alloc.free(signed_bytes);

        var veri = rsa.PKCS1v15(TestHash).Signature.fromBytes(signed_bytes);
        try veri.verifyPrehashed(h_msg, pub_key);
    }

    {
        var kp = try rsa.KeyPair.fromSecretKey(pri_key);
        var sig = try kp.signPss(alloc, random, TestHash, msg, .{});

        const signed_bytes = sig.toBytes();
        try testing.expectEqual(true, signed_bytes.len > 0);

        defer alloc.free(signed_bytes);

        var veri = rsa.Pss(TestHash).Signature.fromBytes(signed_bytes);
        try veri.verify(msg, pub_key, .{});
    }

    {
        var kp = try rsa.KeyPair.fromSecretKey(pri_key);
        var sig = try kp.signPkcs1v15(alloc, TestHash, msg);

        const signed_bytes = sig.toBytes();
        try testing.expectEqual(true, signed_bytes.len > 0);

        defer alloc.free(signed_bytes);

        var veri = rsa.PKCS1v15(TestHash).Signature.fromBytes(signed_bytes);
        try veri.verify(msg, pub_key);
    }
}

test "SecretKey from der with precompute" {
    const alloc = testing.allocator;

    {
        const prikey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDh/nCDmXaEqxN416b9XjV8acmbqA52uPzKbesWQRT/BPxEO2dKAURk5CkcSBDskvfzFR9TRjeDppjD1BPSEnuYKnP0SvmotoxcnBnHMfMBqGV8DSJyppu8k4y9C3MPq5C/rA8TJm0NNaJCL0BfAGkeyw+elgYifbRlm42VfYGsKVyIeEI9Qghk5Cf8yapMPfWNLKOhChXsyGExMBMonHZeseFH7UNwonNAFJMAaelhVqqmwBFqn6fBGKmvedRO7HIaiEFNKaMna6xJ5Bccjds4MhF7UC5PIdx4Bt7CfxvjrbIRYoBF2l30CNBblIhU992zPkHoaVhDkt1gq3OdO7LvAgMBAAECggEBALCJrWTv7ahnZ3efpqAIBuogTVBd8KaHjVmokds5jehFAbdfXClwYfgaT477MNVNXYmzN1w63sTl0DIxqiYRMCFHEHuGUg6cQ3tYqb50Y2spG9XTANTlF4UxEeDfX8ue7xz7kG8aNlf6TL084iEUVgmrAJGWikZJQjGZWPmtKC3OTeJY5Bev5qHVuMRe+XEM5aQc3ph+lXlOF0Qp0Eg8YRWprrev2faH6prMqu2JGomoac6sfM4QJhtEViF7Gw0XPthPTbF19IefuAwi9psMM/9CnQ+MTWN2i6IxoUdicsFuC+Wdlb3K5V/+uldNSr+ePEhcya+YTLK9IOcVwWKQHykCgYEA8XvuEribf+t0ZPtfxr+DC9nZHXbVoFx0/ARpSG+P/fp3Hn3rO9iYQ6OtZ9mEXTzf+dhYTaRWq6PbCOz6i0It+J8QSBdxU9OcQ4871mDe41IvSc1CCGMW4PeIYtNQEK0zrqhN7SMtKyUd7yAsYRCrIzMc7NjE2qJvFw5kh7xC3Q0CgYEA75Qjn5daNYSAOa/ILdOs5J/8oIaO27RNK/fSKm/btsMsyum8+YP/mWmm1MXBzG9WEKzZv5yEKOWCEVJYVsFQsGt9yLYW2WIKU5UxiuU0F1RImF/dphIbYOh7oGC3WfYKk2f+K7ftjc196ZkEkDuE2Xh1h75/67Mzztx1DbXj6OsCgYBcDRfFfyWXb5Og4smxo1M680H2H1RzmorlfnD7sbs733wE3Y8L8xanwf7Z9WqleA0Q2k1e22RGbWGTV3JyHzoS6d90+6qxf5qzjigLIkYUdUGdambfd5ZDD1ioA1Ej6kInM/TwjlYreiyc+LCyF36FHnjKOB9iEEU0jsH3k+YRCQKBgHMVLPuHX6zfhhyvxK/Gw4FbHKYbnNoKxRs+wvThoKAtJwIdv0n4TzppVttUV2CVhrkh3sM9MvrWLGGXtZmO6Oyl5dkZJuarQpydyRuYOCqQsQKI4lbY0c/+PQxwCQMsvi3KwXxMsM7yC+6/M0L5ZDp2s7ZOGvKktVlD6vJ4Eg+bAoGARnGGprSBW8dAb/s53r0paPh4k/bySrXdGEprLwk6g3S8+aylcmjUdjcIq4dEb4A/nv12dx1Sc4y99c62R0zi+TT6FYBIFDMz3HNVzO0Jr6SgC6CNVotL0D725CioR5U1NyTHHRLZth69HLuEZCZQlPJCbePXMRRHmOl1svzcVuo=";
        const prikey_bytes = try base64Decode(alloc, prikey);

        defer alloc.free(prikey_bytes);

        var pri_key = try rsa.SecretKey.fromPKCS8DerWithPrecompute(alloc, prikey_bytes);
        defer pri_key.deinit(alloc);

        var pri_key2 = try rsa.SecretKey.fromDerAutoWithPrecompute(alloc, prikey_bytes);
        defer pri_key2.deinit(alloc);
    }

    {
        const prikey = "MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAyMaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdEKdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gMIvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDnFcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvYmEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghjFuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+UI5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNTOvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL04aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0KcnckbmDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ryeBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq";
        const prikey_bytes = try base64Decode(alloc, prikey);

        defer alloc.free(prikey_bytes);

        var pri_key = try rsa.SecretKey.fromDerWithPrecompute(alloc, prikey_bytes);
        defer pri_key.deinit(alloc);

        var pri_key2 = try rsa.SecretKey.fromDerAutoWithPrecompute(alloc, prikey_bytes);
        defer pri_key2.deinit(alloc);
    }

    {
        const n = try hexDecode(alloc, "9d0f502cf5365bf3949f1bfaa444fa9c9fd0f9126e2d86a753f276e5d5ff813be4f33b88603a6e569b83a363cbb17e0e7c1dd86bc067b9955eec933e08ab75dba44b758a95439e327087d4d5e017c8f79da4d7c7d694ec397fbfeb04a7ee265af15407db70b840aacc03703dc74bf48707f00e781536bf971b61d38d5825838ebd4bed1db8b3f508e15e2e622839b3b0e1fe051b51b2834801df59131e11e7e8cf2120173f4254b9e5a3cab2dcb14f6d4abf087e58876b880eb1d488af21bf80e565939afd08a3ba046444180a955d1f19a40bb51ebcd2a4178df97ee9cf8f145d13d84eef37ea61577e65de80271a3dfc2fbbca2dc5f3ac867aa48c7477b767");
        const e = try hexDecode(alloc, "010001");
        const d = try hexDecode(alloc, "63d392db30747f975f948ddd0e4205a43d743e8b775a1a670a55673b087ca0f0a7c1edc9ed97d5ffd852a02c53109a95ac4feff9f4ce38c7f7109939e99ac98b746ebde3faa182d07e73e754955da8cfb1f44f6e66363bbb0436c0b331e58d9d6a1c45ee3543f75e57d3aba8a89edf6a602235a01fa3afbce49b9632159faa70b570ac22d54af63e1c2f09869d91a0a4cbe4f2f4f0ba6c7469df09a1a121b7044df20b0e90089ae1e4d194bd72c85ead2db6de51b69961b0454b2ed3ac0ed9c1cd75dac818a6cb2d47ec0d950907ad14d68812b4ec83766795369c81fa10eab57c9774bf83f2d9eebc5f96c58d0a864bf005b905cf26deda7c5220754e2ee2b9");
        const p = try hexDecode(alloc, "cc558bc7e22c34a9b5012f75ed39ccb284f2f4a64af78652b5cb6f77999202344161192ae63a5cd048d1943b80b98a66e15142187efc2d471f0f7d258843790d87b190a2a522a299b3b8ccf1d250b3003394d29ff6a9a79bbf9b08219d45969147dad74b44ad223adbebf48a2a0dd9ad394a8838fc8bbadc7025001663e4b46b");
        const q = try hexDecode(alloc, "c4c5b893ac7215a18383cba6b27bb4e0f8a7890649da0c26c317d1703c16ae7f875686002f840857d814d75ada28b7ac54e3b7a1db6af3a8b67b780beb90a32f80eebb839bdeecf309faca921dd00aeb359aa4b1b93c0357df1c52dcd992548f6739b243630a6149293f8480d38b6ce2b4d603dc5d9d21914a08e3cf020067f5");

        defer alloc.free(n);
        defer alloc.free(e);
        defer alloc.free(d);
        defer alloc.free(p);
        defer alloc.free(q);

        var pri_key = try rsa.SecretKey.fromBytesWithPrecompute(alloc, n, e, d, p, q);
        defer pri_key.deinit(alloc);
    }

    {
        const n = try hexDecode(alloc, "9d0f502cf5365bf3949f1bfaa444fa9c9fd0f9126e2d86a753f276e5d5ff813be4f33b88603a6e569b83a363cbb17e0e7c1dd86bc067b9955eec933e08ab75dba44b758a95439e327087d4d5e017c8f79da4d7c7d694ec397fbfeb04a7ee265af15407db70b840aacc03703dc74bf48707f00e781536bf971b61d38d5825838ebd4bed1db8b3f508e15e2e622839b3b0e1fe051b51b2834801df59131e11e7e8cf2120173f4254b9e5a3cab2dcb14f6d4abf087e58876b880eb1d488af21bf80e565939afd08a3ba046444180a955d1f19a40bb51ebcd2a4178df97ee9cf8f145d13d84eef37ea61577e65de80271a3dfc2fbbca2dc5f3ac867aa48c7477b767");
        const e = try hexDecode(alloc, "010001");

        defer alloc.free(n);
        defer alloc.free(e);

        _ = try rsa.PublicKey.fromBytes(n, e);
    }
}

test "PublicKey toDer" {
    const need_run = false;

    if (need_run) {
        try test_pubkey_toder();
        try test_prikey_toder();
    }
}

fn test_pubkey_toder() !void {
    const alloc = testing.allocator;

    const pubkey = "3082010a0282010100c04c85907cca38794d7f6893f60b5ef98a940a7c0b730571a71c46e5971759c3d7070962e09db8b0fcaa007b06118ea332934e6a88694ba9c420f524d226979a2542656a491404190a8d7a0199ed51fbb88659ba9348f2af5c099e535951a96112cc1f6cb8ded3dd75ab4a1acefbace65fd4b697c8a3d2ac941964833b5acb18b073562e9f95e0e2edb0f57644b55c0d12d1d79668e274c31858617f8c13e84b1e71080fc026c1a67b2fd211a569bbbba98fe759eba669017eec17e3bb372086abf965a3392e71377f24cd4ff7ad75925ccf59e9697d7f063a164caf5a2069fb896aa5394314497e30659e509e474a88e5d0eae5eec08ce6458a226765eb64f50203010001";

    const pubkey_bytes = try hexDecode(alloc, pubkey);
    defer alloc.free(pubkey_bytes);

    var pub_key = try rsa.PublicKey.fromDer(pubkey_bytes);

    const pub_key_der = try pub_key.toDer(alloc);
    defer alloc.free(pub_key_der);

    try testing.expectFmt(pubkey, "{x}", .{pub_key_der});
}

fn test_prikey_toder() !void {
    const alloc = testing.allocator;

    const prikey = "308204a50201000282010100c04c85907cca38794d7f6893f60b5ef98a940a7c0b730571a71c46e5971759c3d7070962e09db8b0fcaa007b06118ea332934e6a88694ba9c420f524d226979a2542656a491404190a8d7a0199ed51fbb88659ba9348f2af5c099e535951a96112cc1f6cb8ded3dd75ab4a1acefbace65fd4b697c8a3d2ac941964833b5acb18b073562e9f95e0e2edb0f57644b55c0d12d1d79668e274c31858617f8c13e84b1e71080fc026c1a67b2fd211a569bbbba98fe759eba669017eec17e3bb372086abf965a3392e71377f24cd4ff7ad75925ccf59e9697d7f063a164caf5a2069fb896aa5394314497e30659e509e474a88e5d0eae5eec08ce6458a226765eb64f5020301000102820101009c8a2e786e7d97f77754ee66f476513c46c938b7be02463e3cd1520d782fb40d2eb035bdde27c6bf9d0f2f10f6e1b801b61c204bacfc3a71da8d11c285a890e514cbb60f0daa53a3a6e98096691dbe0d722b3c441bbdd88154252853a5744ab4113f459d95e91f033ad4d3a07b3a7987981f6afca88263efc527dea0cde29d4cf18fa94673fad21dd479d024e1130fce43d587dc9b8ae60a3c7ce03d358ee1bdcef9cc5ee193ca5fa31e66744f2b3dbb64664c22ba1b480c36c860bf14e983f9833ff1cecfefb48375ac32ead071ce7fe741d9f4e35b3569f26682db522447b46e3aedbbf5bb0822883888067bb342a0629a93450c5c0b14ab1d3616bd43918102818100c2a21d19a036d890032c5792aae595ebcf98ae535ea4ba411168eda77542ab1dc26956c10d3f52e6ae180dc838403e89d8f8c1899b649435a64c6b9afcec32214db8b7d49fe05f13ae46c3d067c6825efdda2b794513227d3cd692ff738bcfd63a2f98d44d2af3b21bff62446a8d90ce9fb5aa9ded6907f2fd501de200b2e02502818100fcedfda33cff3e9021ec5906faa7bd99f73eabdb717805d1da37b470ec1eae3789d917bba27882be15f188caa6def93e0ce3ce55077e1e6d486f7f9091a503973f5ccd7bac21bd7aaaf86d0ff3ba280137d9e42c4415c9fbbdd1f55a3bab5df0ba53a062add7c380aa2cb57e2af20a049163eb92026e41df9b7b2f64202db0910281810090b0939189593c8552d69403a4a8285bb5687bafde9bf71a8826c905c4565b7f3417bb36a8f27a5ea2ed9ed1497ff8fde11e8c421013255afcd5b2e8f53d61c7005061d8df419d6cb412475f96c62c0512122e5f68ca60c95980eaa69cef4302af1ed32e806f7ddada9570280c4e516849b273b413da10dec311dc2536ffc341028180625fe670e13e9d84cdccf16b877e4a7e61eddc4603c21cf15c20a26bf14a959440675195c7417c0896dc54ca0d51583bcc23a692e7d123e07975f475b4502c2f5d93a8d05b48dc3ba3d7f0036e568f4cb9fe6382dc10657926814d1e856ac7a4e3b3b703ea7dab2a9605c1a98ae68d02edd1a1442ef1d769333e1c56a335622102818100a2097789b56052857c3b227a76b4fcba0fa1f585be1121e0ea7cf10ad0370ce2e102a48376dee1cbdca25fa78b3abb10fa5d05ec63a192d63442210e74d2b47eddbbb46b681f4351d8a3994f8692044d0635af2172ff0f761a8a25da8c7313704cde454ae859ca083a8b8561480eff7ae53b380e2ad0b4d0dcb9a2fd1480e823";

    const prikey_bytes = try hexDecode(alloc, prikey);
    defer alloc.free(prikey_bytes);

    var pri_key = try rsa.SecretKey.fromDer(alloc, prikey_bytes);
    defer pri_key.deinit(alloc);

    const pri_key_der = try pri_key.toDer(alloc);
    defer alloc.free(pri_key_der);

    try testing.expectFmt(prikey, "{x}", .{pri_key_der});
}
