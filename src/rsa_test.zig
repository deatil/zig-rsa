const std = @import("std");
const fmt = std.fmt;
const testing = std.testing;
const base64 = std.base64;
const hash = std.crypto.hash;
const Random = std.Random;
const Allocator = std.mem.Allocator;

const rsa = @import("rsa.zig");
const utils = @import("utils.zig");

const TestHash = std.crypto.hash.sha2.Sha256;

fn testKeypair() !rsa.KeyPair {
    const keypair_bytes = @embedFile("testdata/id_rsa.der");

    const sk = try rsa.SecretKey.fromDer(keypair_bytes);
    const kp = try rsa.KeyPair.fromSecretKey(sk);

    try std.testing.expectEqual(2048, kp.public_key.n.bits());

    return kp;
}

test "rsa PKCS1-v1_5 encrypt and decrypt" {
    const alloc = testing.allocator;

    const kp = try testKeypair();

    var prng = std.Random.DefaultPrng.init(0xC0FFEE_1234_5678);
    const random = prng.random();

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

    const kp = try testKeypair();

    var prng = std.Random.DefaultPrng.init(0xC0FFEE_1234_5678);
    const random = prng.random();

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

    const kp = try testKeypair();

    var prng = std.Random.DefaultPrng.init(0xC0FFEE_1234_5678);
    const random = prng.random();

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

fn base64Decode(alloc: Allocator, input: []const u8) ![]const u8 {
    const decoder = base64.standard.Decoder;
    const decode_len = try decoder.calcSizeForSlice(input);

    const buffer = try alloc.alloc(u8, decode_len);
    _ = decoder.decode(buffer, input) catch {
        return "";
    };

    return buffer[0..];
}

test "Signer with pkcs8 key" {
    const alloc = testing.allocator;

    const prikey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDh/nCDmXaEqxN416b9XjV8acmbqA52uPzKbesWQRT/BPxEO2dKAURk5CkcSBDskvfzFR9TRjeDppjD1BPSEnuYKnP0SvmotoxcnBnHMfMBqGV8DSJyppu8k4y9C3MPq5C/rA8TJm0NNaJCL0BfAGkeyw+elgYifbRlm42VfYGsKVyIeEI9Qghk5Cf8yapMPfWNLKOhChXsyGExMBMonHZeseFH7UNwonNAFJMAaelhVqqmwBFqn6fBGKmvedRO7HIaiEFNKaMna6xJ5Bccjds4MhF7UC5PIdx4Bt7CfxvjrbIRYoBF2l30CNBblIhU992zPkHoaVhDkt1gq3OdO7LvAgMBAAECggEBALCJrWTv7ahnZ3efpqAIBuogTVBd8KaHjVmokds5jehFAbdfXClwYfgaT477MNVNXYmzN1w63sTl0DIxqiYRMCFHEHuGUg6cQ3tYqb50Y2spG9XTANTlF4UxEeDfX8ue7xz7kG8aNlf6TL084iEUVgmrAJGWikZJQjGZWPmtKC3OTeJY5Bev5qHVuMRe+XEM5aQc3ph+lXlOF0Qp0Eg8YRWprrev2faH6prMqu2JGomoac6sfM4QJhtEViF7Gw0XPthPTbF19IefuAwi9psMM/9CnQ+MTWN2i6IxoUdicsFuC+Wdlb3K5V/+uldNSr+ePEhcya+YTLK9IOcVwWKQHykCgYEA8XvuEribf+t0ZPtfxr+DC9nZHXbVoFx0/ARpSG+P/fp3Hn3rO9iYQ6OtZ9mEXTzf+dhYTaRWq6PbCOz6i0It+J8QSBdxU9OcQ4871mDe41IvSc1CCGMW4PeIYtNQEK0zrqhN7SMtKyUd7yAsYRCrIzMc7NjE2qJvFw5kh7xC3Q0CgYEA75Qjn5daNYSAOa/ILdOs5J/8oIaO27RNK/fSKm/btsMsyum8+YP/mWmm1MXBzG9WEKzZv5yEKOWCEVJYVsFQsGt9yLYW2WIKU5UxiuU0F1RImF/dphIbYOh7oGC3WfYKk2f+K7ftjc196ZkEkDuE2Xh1h75/67Mzztx1DbXj6OsCgYBcDRfFfyWXb5Og4smxo1M680H2H1RzmorlfnD7sbs733wE3Y8L8xanwf7Z9WqleA0Q2k1e22RGbWGTV3JyHzoS6d90+6qxf5qzjigLIkYUdUGdambfd5ZDD1ioA1Ej6kInM/TwjlYreiyc+LCyF36FHnjKOB9iEEU0jsH3k+YRCQKBgHMVLPuHX6zfhhyvxK/Gw4FbHKYbnNoKxRs+wvThoKAtJwIdv0n4TzppVttUV2CVhrkh3sM9MvrWLGGXtZmO6Oyl5dkZJuarQpydyRuYOCqQsQKI4lbY0c/+PQxwCQMsvi3KwXxMsM7yC+6/M0L5ZDp2s7ZOGvKktVlD6vJ4Eg+bAoGARnGGprSBW8dAb/s53r0paPh4k/bySrXdGEprLwk6g3S8+aylcmjUdjcIq4dEb4A/nv12dx1Sc4y99c62R0zi+TT6FYBIFDMz3HNVzO0Jr6SgC6CNVotL0D725CioR5U1NyTHHRLZth69HLuEZCZQlPJCbePXMRRHmOl1svzcVuo=";
    const pubkey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";

    const prikey_bytes = try base64Decode(alloc, prikey);
    const pubkey_bytes = try base64Decode(alloc, pubkey);

    defer alloc.free(prikey_bytes);
    defer alloc.free(pubkey_bytes);

    const pri_key = try rsa.SecretKey.fromPKCS8Der(prikey_bytes);
    const pub_key = try rsa.PublicKey.fromPKCS8Der(pubkey_bytes);

    var prng = std.Random.DefaultPrng.init(0xC0FFEE_1234_5678);
    const random = prng.random();

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

    const prikey_bytes = try base64Decode(alloc, prikey);
    const pubkey_bytes = try base64Decode(alloc, pubkey);

    defer alloc.free(prikey_bytes);
    defer alloc.free(pubkey_bytes);

    const pri_key = try rsa.SecretKey.fromDerAuto(prikey_bytes);
    const pub_key = try rsa.PublicKey.fromDerAuto(pubkey_bytes);

    try std.testing.expectEqual(256, pri_key.public_key.size());
    try std.testing.expectEqual(256, pub_key.size());

    var prng = std.Random.DefaultPrng.init(0xC0FFEE_1234_5678);
    const random = prng.random();

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

    var pri_key = try rsa.SecretKey.fromPKCS8Der(prikey_bytes);
    try pri_key.precompute(alloc);

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

    // var pub_key = pri_key.public_key;
    // const pub_key_der = try pub_key.makeDer(alloc);
    // defer alloc.free(pub_key_der);

    // const pri_key2 = try rsa.SecretKey.fromDer(pub_key_der);
    // try std.testing.expectEqual(8, pri_key2.len);
}

test "SecretKey validate" {
    const alloc = testing.allocator;

    const prikey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDh/nCDmXaEqxN416b9XjV8acmbqA52uPzKbesWQRT/BPxEO2dKAURk5CkcSBDskvfzFR9TRjeDppjD1BPSEnuYKnP0SvmotoxcnBnHMfMBqGV8DSJyppu8k4y9C3MPq5C/rA8TJm0NNaJCL0BfAGkeyw+elgYifbRlm42VfYGsKVyIeEI9Qghk5Cf8yapMPfWNLKOhChXsyGExMBMonHZeseFH7UNwonNAFJMAaelhVqqmwBFqn6fBGKmvedRO7HIaiEFNKaMna6xJ5Bccjds4MhF7UC5PIdx4Bt7CfxvjrbIRYoBF2l30CNBblIhU992zPkHoaVhDkt1gq3OdO7LvAgMBAAECggEBALCJrWTv7ahnZ3efpqAIBuogTVBd8KaHjVmokds5jehFAbdfXClwYfgaT477MNVNXYmzN1w63sTl0DIxqiYRMCFHEHuGUg6cQ3tYqb50Y2spG9XTANTlF4UxEeDfX8ue7xz7kG8aNlf6TL084iEUVgmrAJGWikZJQjGZWPmtKC3OTeJY5Bev5qHVuMRe+XEM5aQc3ph+lXlOF0Qp0Eg8YRWprrev2faH6prMqu2JGomoac6sfM4QJhtEViF7Gw0XPthPTbF19IefuAwi9psMM/9CnQ+MTWN2i6IxoUdicsFuC+Wdlb3K5V/+uldNSr+ePEhcya+YTLK9IOcVwWKQHykCgYEA8XvuEribf+t0ZPtfxr+DC9nZHXbVoFx0/ARpSG+P/fp3Hn3rO9iYQ6OtZ9mEXTzf+dhYTaRWq6PbCOz6i0It+J8QSBdxU9OcQ4871mDe41IvSc1CCGMW4PeIYtNQEK0zrqhN7SMtKyUd7yAsYRCrIzMc7NjE2qJvFw5kh7xC3Q0CgYEA75Qjn5daNYSAOa/ILdOs5J/8oIaO27RNK/fSKm/btsMsyum8+YP/mWmm1MXBzG9WEKzZv5yEKOWCEVJYVsFQsGt9yLYW2WIKU5UxiuU0F1RImF/dphIbYOh7oGC3WfYKk2f+K7ftjc196ZkEkDuE2Xh1h75/67Mzztx1DbXj6OsCgYBcDRfFfyWXb5Og4smxo1M680H2H1RzmorlfnD7sbs733wE3Y8L8xanwf7Z9WqleA0Q2k1e22RGbWGTV3JyHzoS6d90+6qxf5qzjigLIkYUdUGdambfd5ZDD1ioA1Ej6kInM/TwjlYreiyc+LCyF36FHnjKOB9iEEU0jsH3k+YRCQKBgHMVLPuHX6zfhhyvxK/Gw4FbHKYbnNoKxRs+wvThoKAtJwIdv0n4TzppVttUV2CVhrkh3sM9MvrWLGGXtZmO6Oyl5dkZJuarQpydyRuYOCqQsQKI4lbY0c/+PQxwCQMsvi3KwXxMsM7yC+6/M0L5ZDp2s7ZOGvKktVlD6vJ4Eg+bAoGARnGGprSBW8dAb/s53r0paPh4k/bySrXdGEprLwk6g3S8+aylcmjUdjcIq4dEb4A/nv12dx1Sc4y99c62R0zi+TT6FYBIFDMz3HNVzO0Jr6SgC6CNVotL0D725CioR5U1NyTHHRLZth69HLuEZCZQlPJCbePXMRRHmOl1svzcVuo=";

    const prikey_bytes = try base64Decode(alloc, prikey);

    defer alloc.free(prikey_bytes);

    var pri_key = try rsa.SecretKey.fromPKCS8Der(prikey_bytes);
    try pri_key.validate();
}

test "KeyPair generate" {
    const alloc = testing.allocator;

    var prng = std.Random.DefaultPrng.init(0xC0FFEE_1234_5678);
    const random = prng.random();

    const kp = try rsa.KeyPair.generate(alloc, random, 1024);

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

    var prng = std.Random.DefaultPrng.init(0xC0FFEE_1234_5678);
    const random = prng.random();

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

    var prng = std.Random.DefaultPrng.init(0xC0FFEE_1234_5678);
    const random = prng.random();

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

    const kp = try testKeypair();

    var prng = std.Random.DefaultPrng.init(0xC0FFEE_1234_5678);
    const random = prng.random();

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

    var prng = std.Random.DefaultPrng.init(0xC0FFEE_1234_5678);
    const random = prng.random();

    const kp = try rsa.generate_key(alloc, random, 1024);

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

    var prng = std.Random.DefaultPrng.init(0xC0FFEE_1234_5678);
    const random = prng.random();

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

        var pri_key = try rsa.SecretKey.fromDer(prikey_bytes);
        try pri_key.precompute(alloc);

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

    var pri_key = try rsa.SecretKey.fromDer(prikey_bytes);
    try pri_key.precompute(alloc);

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

    var prng = std.Random.DefaultPrng.init(0xC0FFEE_1234_5678);
    const random = prng.random();

    const kp = try rsa.KeyPair.generate(alloc, random, 1024);
    const pri_key = kp.secret_key;
    const pub_key = kp.public_key;

    {
        const pri_key2 = kp.secret_key;
        const pub_key2 = pri_key.public();

        try std.testing.expectEqual(true, pri_key2.equal(pri_key));
        try std.testing.expectEqual(true, pub_key2.equal(pub_key));
    }

    {
        const kp2 = try rsa.KeyPair.generate(alloc, random, 1024);

        try std.testing.expectEqual(false, kp2.secret_key.equal(pri_key));
        try std.testing.expectEqual(false, kp2.public_key.equal(pub_key));
    }
}
