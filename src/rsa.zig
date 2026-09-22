const std = @import("std");
const fmt = std.fmt;
const ff = std.crypto.ff;
const testing = std.testing;
const asn1 = std.crypto.codecs.asn1;
const sha2 = std.crypto.hash.sha2;
const sha3 = std.crypto.hash.sha3;
const Random = std.Random;
const Allocator = std.mem.Allocator;

pub const der = @import("der.zig");
pub const oids = @import("oid.zig");
pub const utils = @import("utils.zig");
pub const subtle = @import("subtle.zig");

pub const max_modulus_bits = 4096;
pub const max_modulus_len = max_modulus_bits / 8;

pub const FeUint = ff.Uint(max_modulus_bits);
pub const Modulus = ff.Modulus(max_modulus_bits);
pub const Fe = Modulus.Fe;

pub const BigInt = std.math.big.int.Managed;

pub const RsaSha256 = PKCS1v15(sha2.Sha256);
pub const RsaSha384 = PKCS1v15(sha2.Sha384);
pub const RsaSha512 = PKCS1v15(sha2.Sha512);

pub const PssSha256 = Pss(sha2.Sha256);
pub const PssSha384 = Pss(sha2.Sha384);
pub const PssSha512 = Pss(sha2.Sha512);

pub const X931Sha256 = X931(sha2.Sha256);
pub const X931Sha384 = X931(sha2.Sha384);
pub const X931Sha512 = X931(sha2.Sha512);

// Pkcs1PrivateKey is a structure which mirrors the PKCS #1 ASN.1 for an RSA private key.
const Pkcs1PrivateKey = struct {
    version: asn1.Opaque(asn1.Tag.universal(.integer, false)),
    n: asn1.Opaque(asn1.Tag.universal(.integer, false)),
    e: asn1.Opaque(asn1.Tag.universal(.integer, false)),
    d: asn1.Opaque(asn1.Tag.universal(.integer, false)),
    p: asn1.Opaque(asn1.Tag.universal(.integer, false)),
    q: asn1.Opaque(asn1.Tag.universal(.integer, false)),
};

// Pkcs1PublicKey reflects the ASN.1 structure of a PKCS #1 public key.
const Pkcs1PublicKey = struct {
    n: asn1.Opaque(asn1.Tag.universal(.integer, false)),
    e: asn1.Opaque(asn1.Tag.universal(.integer, false)),
};

pub const PublicKey = struct {
    n: Modulus,
    e: Fe,

    const Self = @This();

    pub fn size(self: Self) usize {
        return utils.byteLen(self.n.bits());
    }

    // equal reports whether pub and x have the same value.
    // In V, we'll accept a PublicKey for equality check.
    pub fn equal(self: Self, x: Self) bool {
        if (self.n.v.eql(x.n.v) and self.e.eql(x.e)) {
            return true;
        }

        return false;
    }

    pub fn fromBytes(mod: []const u8, exp: []const u8) !Self {
        const n = try Modulus.fromBytes(mod, .big);
        if (n.bits() < 512) {
            return error.RsaInsecureBitCount;
        }

        const e = try Fe.fromBytes(n, exp, .big);

        return .{
            .n = n,
            .e = e,
        };
    }

    pub fn fromDer(bytes: []const u8) !Self {
        var parser = der.Parser{ .bytes = bytes };

        const seq = try parser.expectSequence();
        defer parser.seek(seq.slice.end);

        const modulus = try parser.expectPrimitive(.integer);
        const pub_exp = try parser.expectPrimitive(.integer);

        const n = parser.view(modulus);
        const e = parser.view(pub_exp);

        return Self.fromBytes(n, e);
    }

    pub fn fromPKCS8Der(bytes: []const u8) !Self {
        var parser = der.Parser{ .bytes = bytes };
        _ = try parser.expectSequence();

        const oid_seq = try parser.expectSequence();
        const oid = try parser.expectOid();

        try checkRSAPublickeyOid(oid);

        parser.seek(oid_seq.slice.end);
        const pubkey = try parser.expectBitstring();

        return Self.fromDer(pubkey.bytes);
    }

    pub fn fromDerAuto(bytes: []const u8) !Self {
        const pk = Self.fromPKCS8Der(bytes) catch {
            return Self.fromDer(bytes);
        };

        return pk;
    }

    pub fn toDer(self: Self, alloc: Allocator) ![]const u8 {
        var n_buf: [max_modulus_len]u8 = undefined;
        try self.n.toBytes(&n_buf, .big);
        const new_n_buf = utils.stripLeadingZeros(&n_buf);

        var e_buf: [max_modulus_len]u8 = undefined;
        try self.e.toBytes(&e_buf, .big);
        const new_e_buf = utils.stripLeadingZeros(&e_buf);

        const value = Pkcs1PublicKey{
            .n = .{ .bytes = new_n_buf },
            .e = .{ .bytes = new_e_buf },
        };

        const ders = try asn1.der.encode(alloc, value);
        return ders;
    }

    pub fn check(self: Self) !void {
        if (self.n.v.isZero()) {
            return error.RsaMissingPublicModulus;
        }

        // > the RSA public exponent e is an integer between 3 and n - 1 satisfying
        // > GCD(e,\lambda(n)) = 1, where \lambda(n) = LCM(r_1 - 1, ..., r_u - 1)
        const e_v = self.e.toPrimitive(u32) catch return error.RsaExponent;
        if (!self.e.isOdd()) return error.RsaExponent;
        if (e_v < 2) return error.RsaPublicExponentTooSmall;
        if (self.n.v.compare(self.e.v) == .lt) return error.RsaExponent;
    }
};

pub const SecretKey = struct {
    public_key: PublicKey,
    d: Fe,
    primes: []Fe,

    // Precomputed contains precomputed values that speed up private
    // operations, if available.
    precomputed: ?PrecomputedValues = null,

    const Self = @This();

    pub fn deinit(self: *Self, alloc: Allocator) void {
        alloc.free(self.primes);

        if (self.precomputed) |precomputed| {
            alloc.free(precomputed.crt_values);
        }
    }

    pub fn public(self: Self) PublicKey {
        return self.public_key;
    }

    // equal reports whether priv and x have equivalent values. It ignores
    // Precomputed values.
    pub fn equal(self: Self, x: Self) bool {
        if (!self.public_key.equal(x.public_key) or !self.d.eql(x.d)) {
            return false;
        }

        if (self.primes.len != x.primes.len) {
            return false;
        }

        var i: usize = 0;
        while (i < self.primes.len) : (i += 1) {
            if (!self.primes[i].eql(x.primes[i])) {
                return false;
            }
        }

        return true;
    }

    pub fn fromBytes(
        alloc: Allocator,
        n: []const u8,
        e: []const u8,
        d: []const u8,
        p: []const u8,
        q: []const u8,
    ) !Self {
        var seckey = try Self.fromBytesInternal(alloc, n, e, d, p, q);
        try seckey.precompute(alloc);
        return seckey;
    }

    pub fn fromDer(alloc: Allocator, bytes: []const u8) !Self {
        var parser = der.Parser{ .bytes = bytes };
        _ = try parser.expectSequence();
        const version = try parser.expectInt(u8);

        const mod = try parser.expectPrimitive(.integer);
        const pub_exp = try parser.expectPrimitive(.integer);

        const sec_exp = try parser.expectPrimitive(.integer);
        const prime1 = try parser.expectPrimitive(.integer);
        const prime2 = try parser.expectPrimitive(.integer);

        if (version > 1) {
            return error.RsaInvalidVersion;
        }

        const n = parser.view(mod);
        const e = parser.view(pub_exp);

        const d = parser.view(sec_exp);
        const p = parser.view(prime1);
        const q = parser.view(prime2);

        var seckey = try Self.fromBytesInternal(alloc, n, e, d, p, q);

        if (version == 0) {
            try seckey.precompute(alloc);
            return seckey;
        }

        defer seckey.deinit(alloc);

        const dp = try parser.expectPrimitive(.integer);
        const dq = try parser.expectPrimitive(.integer);
        const qinv = try parser.expectPrimitive(.integer);
        _ = .{ dp, dq, qinv };

        var primes = try std.ArrayList(Fe).initCapacity(alloc, 0);
        defer primes.deinit(alloc);

        try primes.append(alloc, seckey.primes[0]);
        try primes.append(alloc, seckey.primes[1]);

        const crts_seq = try parser.expectSequence();

        var crts_parser = der.Parser{
            .bytes = parser.view(crts_seq),
        };

        while (!crts_parser.eof()) {
            const prime_seq = try crts_parser.expectSequence();

            // get crts first
            const prime_int = try crts_parser.expectPrimitive(.integer);
            const prime_bytes = crts_parser.view(prime_int);

            // crt_seq = [prime, exp, coeff]
            const prime = try Fe.fromBytes(seckey.public_key.n, prime_bytes, .big);
            try primes.append(alloc, prime);

            crts_parser.seek(prime_seq.slice.end);
        }

        var seckey2: Self = .{
            .public_key = seckey.public_key,
            .d = seckey.d,
            .primes = try primes.toOwnedSlice(alloc),
        };
        try seckey2.precompute(alloc);

        return seckey2;
    }

    pub fn fromPKCS8Der(alloc: Allocator, bytes: []const u8) !Self {
        var parser = der.Parser{ .bytes = bytes };
        _ = try parser.expectSequence();

        const version = try parser.expectInt(u8);
        if (version != 0) {
            return error.RsaPKCS8VersionError;
        }

        const oid_seq = try parser.expectSequence();
        const oid = try parser.expectOid();

        try checkRSAPublickeyOid(oid);

        parser.seek(oid_seq.slice.end);
        const prikey = try parser.expect(.universal, false, .octetstring);

        const prikey_bytes = parser.view(prikey);
        return Self.fromDer(alloc, prikey_bytes);
    }

    pub fn fromDerAuto(alloc: Allocator, bytes: []const u8) !Self {
        const sk = Self.fromPKCS8Der(alloc, bytes) catch {
            return Self.fromDer(alloc, bytes);
        };

        return sk;
    }

    fn fromBytesInternal(
        alloc: Allocator,
        nbytes: []const u8,
        ebytes: []const u8,
        dbytes: []const u8,
        pbytes: []const u8,
        qbytes: []const u8,
    ) !Self {
        const pubkey = try PublicKey.fromBytes(nbytes, ebytes);

        const d = try Fe.fromBytes(pubkey.n, dbytes, .big);
        const p = try Fe.fromBytes(pubkey.n, pbytes, .big);
        const q = try Fe.fromBytes(pubkey.n, qbytes, .big);

        // > The RSA private exponent d is a positive integer less than n
        // > satisfying e * d == 1 (mod \lambda(n)),
        if (!d.isOdd()) return error.RsaExponent;
        if (d.v.compare(pubkey.n.v) != .lt) return error.RsaExponent;

        const primes = [_]Fe{ p, q };

        return .{
            .public_key = pubkey,
            .d = d,
            .primes = try alloc.dupe(Fe, primes[0..]),
        };
    }

    pub fn toDer(self: Self, alloc: Allocator) ![]const u8 {
        var n_buf: [max_modulus_len]u8 = undefined;
        try self.public_key.n.toBytes(&n_buf, .big);
        const new_n_buf = utils.stripLeadingZeros(&n_buf);

        var e_buf: [max_modulus_len]u8 = undefined;
        try self.public_key.e.toBytes(&e_buf, .big);
        const new_e_buf = utils.stripLeadingZeros(&e_buf);

        var d_buf: [max_modulus_len]u8 = undefined;
        try self.d.toBytes(&d_buf, .big);
        const new_d_buf = utils.stripLeadingZeros(&d_buf);

        var p_buf: [max_modulus_len]u8 = undefined;
        try self.puprimes[0].toBytes(&p_buf, .big);
        const new_p_buf = utils.stripLeadingZeros(&p_buf);

        var q_buf: [max_modulus_len]u8 = undefined;
        try self.primes[1].toBytes(&q_buf, .big);
        const new_q_buf = utils.stripLeadingZeros(&q_buf);

        const value = Pkcs1PrivateKey{
            .version = .{ .bytes = []u8{0x00} },
            .n = .{ .bytes = new_n_buf },
            .e = .{ .bytes = new_e_buf },
            .d = .{ .bytes = new_d_buf },
            .p = .{ .bytes = new_p_buf },
            .q = .{ .bytes = new_q_buf },
        };

        const ders = try asn1.der.encode(alloc, value);
        return ders;
    }

    pub fn validate(self: Self) !void {
        try self.public_key.check();
    }

    // Precompute performs some calculations that speed up private key operations
    // in the future.
    pub fn precompute(self: *Self, alloc: Allocator) !void {
        if (self.primes.len < 2) {
            return error.RsaInvalidKey;
        }

        if (self.primes.len > 2) {
            return self.precomputeLegacy(alloc);
        }

        var bd = try utils.bigFromFe(alloc, self.d);
        var bp = try utils.bigFromFe(alloc, self.primes[0]);
        var bq = try utils.bigFromFe(alloc, self.primes[1]);

        defer bd.deinit();
        defer bp.deinit();
        defer bq.deinit();

        var quot = try utils.newBig(alloc);

        // dP = d mod (p-1)
        var bdp = try utils.newBig(alloc);
        try bdp.addScalar(&bp, -1);
        try quot.divFloor(&bdp, &bd, &bdp);

        // dQ = d mod (q-1)
        var bdq = try utils.newBig(alloc);
        try bdq.addScalar(&bq, -1);
        try quot.divFloor(&bdq, &bd, &bdq);

        defer quot.deinit();
        defer bdp.deinit();
        defer bdq.deinit();

        const dp = try utils.feFromBig(self.public_key.n, &bdp);
        const dq = try utils.feFromBig(self.public_key.n, &bdq);

        if (dp.isZero() or dq.isZero()) {
            return error.RsaPrecomputeFail;
        }

        var bqinv = try utils.bigModInverse(alloc, &bq, &bp);
        defer bqinv.deinit();

        const qinv = try utils.feFromBig(self.public_key.n, &bqinv);

        if (qinv.isZero()) {
            return error.RsaPrecomputeFail;
        }

        var crts = [_]CRTValue{};

        const precomputed: PrecomputedValues = .{
            .dp = dp,
            .dq = dq,
            .qinv = qinv,

            .crt_values = &crts,
        };

        self.precomputed = precomputed;
    }

    // precompute CRTValue
    fn precomputeLegacy(self: *Self, alloc: Allocator) !void {
        if (self.primes.len < 2) {
            return error.RsaInvalidKey;
        }

        var bd = try utils.bigFromFe(alloc, self.d);
        var bp = try utils.bigFromFe(alloc, self.primes[0]);
        var bq = try utils.bigFromFe(alloc, self.primes[1]);

        defer bd.deinit();
        defer bp.deinit();
        defer bq.deinit();

        var quot = try utils.newBig(alloc);

        // dP = d mod (p-1)
        var bdp = try utils.newBig(alloc);
        try bdp.addScalar(&bp, -1);
        try quot.divFloor(&bdp, &bd, &bdp);

        // dQ = d mod (q-1)
        var bdq = try utils.newBig(alloc);
        try bdq.addScalar(&bq, -1);
        try quot.divFloor(&bdq, &bd, &bdq);

        defer quot.deinit();
        defer bdp.deinit();
        defer bdq.deinit();

        const dp = try utils.feFromBig(self.public_key.n, &bdp);
        const dq = try utils.feFromBig(self.public_key.n, &bdq);

        if (dp.isZero() or dq.isZero()) {
            return error.RsaPrecomputeFail;
        }

        var bqinv = try utils.bigModInverse(alloc, &bq, &bp);
        defer bqinv.deinit();

        const qinv = try utils.feFromBig(self.public_key.n, &bqinv);

        if (qinv.isZero()) {
            return error.RsaPrecomputeFail;
        }

        var crts = try std.ArrayList(CRTValue).initCapacity(alloc, 0);
        defer crts.deinit(alloc);

        var r = try utils.newBig(alloc);
        try r.mul(&bp, &bq);

        defer r.deinit();

        var i: usize = 2;
        while (i < self.primes.len) : (i += 1) {
            var prime = try utils.bigFromFe(alloc, self.primes[i]);
            defer prime.deinit();

            var exp = try utils.newBig(alloc);
            try exp.addScalar(&prime, -1);
            try quot.divFloor(&exp, &bd, &exp);
            defer exp.deinit();

            var coeff = try utils.bigModInverse(alloc, &r, &prime);
            defer coeff.deinit();

            var r2 = try r.clone();
            if (!r2.isOdd()) {
                try r2.addScalar(&r2, 51);
            } else {
                try r2.addScalar(&r2, 50);
            }
            defer r2.deinit();

            const rr = try utils.modulusFromBig(&r2);

            try crts.append(alloc, .{
                .exp = try utils.feFromBig(self.public_key.n, &exp),
                .coeff = try utils.feFromBig(self.public_key.n, &coeff),
                .r = try utils.feFromBig(rr, &r),
            });

            try r.mul(&r, &prime);
        }

        const precomputed: PrecomputedValues = .{
            .dp = dp,
            .dq = dq,
            .qinv = qinv,

            .crt_values = try crts.toOwnedSlice(alloc),
        };

        self.precomputed = precomputed;
    }
};

pub const PrecomputedValues = struct {
    dp: Fe, // D mod (P-1)
    dq: Fe, // D mod (Q-1)
    qinv: Fe, // Q^-1 mod P

    // CRTValues is used for the 3rd and subsequent primes. Due to a
    // historical accident, the CRT for the first two primes is handled
    // differently in PKCS #1 and interoperability is sufficiently
    // important that we mirror this.
    crt_values: []CRTValue,
};

pub const CRTValue = struct {
    exp: Fe, // D mod (prime-1).
    coeff: Fe, // R·Coeff ≡ 1 mod Prime.
    r: Fe, // product of primes prior to this (inc p and q).
};

pub const KeyPair = struct {
    public_key: PublicKey,
    secret_key: SecretKey,

    const Self = @This();

    pub fn generate(alloc: Allocator, random: Random, bits: usize) !Self {
        if (bits < utils.min_modulus_bits or bits > utils.max_modulus_bits or bits % 2 != 0) {
            return error.RsaInvalidBits;
        }

        const e: u64 = 65537;

        const half = bits / 2;
        const half_len = utils.byteLen(half);

        var e_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &e_bytes, e, .big);

        var p_buf: [max_modulus_len]u8 = undefined;
        defer std.crypto.secureZero(u8, p_buf[0..half_len]);

        var q_buf: [max_modulus_len]u8 = undefined;
        defer std.crypto.secureZero(u8, q_buf[0..half_len]);

        const p_bytes = p_buf[0..half_len];
        const q_bytes = q_buf[0..half_len];

        while (true) {
            utils.generatePrime(random, half, e, p_bytes);
            while (true) {
                utils.generatePrime(random, half, e, q_bytes);
                if (!utils.topBitsMatch(p_bytes, q_bytes)) {
                    break;
                }
            }

            const pb = utils.stripLeadingZeros(p_bytes);
            const qb = utils.stripLeadingZeros(q_bytes);
            const eb = utils.stripLeadingZeros(&e_bytes);

            if (pb.len > max_modulus_len or qb.len > max_modulus_len) {
                continue;
            }
            // e must be odd and >= 3 (RFC 8017 §3.1); evenness would also fail the
            // gcd check below, but reject early and explicitly.
            if (eb.len == 0 or eb[eb.len - 1] & 1 == 0) {
                continue;
            }
            if (eb.len == 1 and eb[0] < 3) {
                continue;
            }

            var bp = try utils.bigFromBytes(alloc, pb);
            var bq = try utils.bigFromBytes(alloc, qb);
            var be = try utils.bigFromBytes(alloc, eb);
            if (bp.order(bq) == .eq) {
                continue;
            } // p == q

            var bn = try utils.newBig(alloc);
            try bn.mul(&bp, &bq);
            if (bn.bitCountAbs() > max_modulus_bits) {
                continue;
            }
            var n_buf: [max_modulus_len]u8 = undefined;
            bn.toConst().writeTwosComplement(&n_buf, .big);
            const n = Modulus.fromBytes(&n_buf, .big) catch {
                continue;
            };

            // λ(n) = lcm(p-1, q-1) = (p-1)(q-1) / gcd(p-1, q-1).
            var p1 = try utils.newBig(alloc);
            try p1.addScalar(&bp, -1);
            var q1 = try utils.newBig(alloc);
            try q1.addScalar(&bq, -1);
            var g = try utils.newBig(alloc);
            try g.gcd(&p1, &q1);
            var phi = try utils.newBig(alloc);
            try phi.mul(&p1, &q1);
            var lambda = try utils.newBig(alloc);
            var rem = try utils.newBig(alloc);
            try lambda.divFloor(&rem, &phi, &g); // exact: g | (p-1)(q-1)

            // d = e⁻¹ mod λ(n); also proves gcd(e, λ(n)) = 1.
            var bd = try utils.bigModInverse(alloc, &be, &lambda);
            if (bd.eqlZero()) {
                continue;
            }

            defer bp.deinit();
            defer bq.deinit();
            defer be.deinit();
            defer bn.deinit();
            defer p1.deinit();
            defer q1.deinit();
            defer g.deinit();
            defer phi.deinit();
            defer lambda.deinit();
            defer rem.deinit();
            defer bd.deinit();

            const d = try utils.feFromBig(n, &bd);

            const fe_e = try Fe.fromBytes(n, &e_bytes, .big);
            const fe_p = try Fe.fromBytes(n, p_bytes, .big);
            const fe_q = try Fe.fromBytes(n, q_bytes, .big);

            const pk = PublicKey{
                .n = n,
                .e = fe_e,
            };

            var primes = [_]Fe{ fe_p, fe_q };

            var sk = SecretKey{
                .public_key = pk,
                .d = d,
                .primes = try alloc.dupe(Fe, primes[0..]),
            };
            try sk.precompute(alloc);

            return .{
                .public_key = pk,
                .secret_key = sk,
            };
        }
    }

    pub fn generateMultiPrimeKey(alloc: Allocator, random: Random, bits: usize, nprimes: usize) !Self {
        const e: u64 = 65537;
        if (nprimes < 2) {
            return error.RsaNrimesMustBeGeTwo;
        }

        if (bits < 64) {
            const primeLimit: f64 = @floatFromInt(@as(u64, 1) << @as(u6, @intCast(bits / nprimes)));
            var pi = primeLimit / (@log(primeLimit) - 1.0);
            pi /= 4.0;
            pi /= 2.0;

            const nprimes2: f64 = @floatFromInt(nprimes);
            if (pi <= nprimes2) {
                return error.RsaTooFewPrimes;
            }
        }

        var primes = try alloc.alloc(BigInt, nprimes);
        defer alloc.free(primes);

        var eInt = try utils.bigFromInt(alloc, e);
        defer eInt.deinit();

        var primeBuf: [max_modulus_len]u8 = undefined;

        var priv: Self = undefined;

        while (true) {
            var todo = bits;

            if (nprimes >= 7) {
                todo += @divFloor((nprimes - 2), 5);
            }

            var i: usize = 0;
            while (i < nprimes) : (i += 1) {
                const primCount = todo / (nprimes - i);
                const primeLen = utils.byteLen(primCount);

                // todo: when std have check randPrime api
                const primeBytes = primeBuf[0..primeLen];
                utils.generatePrime(random, primCount, e, primeBytes);
                // try utils.randPrime(random, primCount, primeBytes);

                defer std.crypto.secureZero(u8, primeBuf[0..]);

                const pb = utils.stripLeadingZeros(primeBytes);

                primes[i] = try utils.bigFromBytes(alloc, pb);
                todo -= primes[i].bitCountAbs();
            }

            for (primes, 0..) |prime, ii| {
                var j: usize = 0;
                while (j < ii) : (j += 1) {
                    if (prime.eql(primes[j])) {
                        continue;
                    }
                }
            }

            var n = try utils.bigFromInt(alloc, 1);
            var totient = try utils.bigFromInt(alloc, 1);

            defer n.deinit();
            defer totient.deinit();

            for (primes) |prime| {
                try n.mul(&n, &prime);

                var pminus1 = try utils.newBig(alloc);
                try pminus1.addScalar(&prime, -1);
                defer pminus1.deinit();

                try totient.mul(&totient, &pminus1);
            }

            if (n.bitCountAbs() != bits) {
                continue;
            }

            var d = utils.bigModInverse(alloc, &eInt, &totient) catch {
                continue;
            };
            defer d.deinit();

            const nMod = try utils.modulusFromBig(&n);
            const eFe = try utils.feFromBig(nMod, &eInt);
            const dFe = try utils.feFromBig(nMod, &d);

            var primesFe = try alloc.alloc(Fe, nprimes);
            defer alloc.free(primesFe);

            for (primes, 0..) |prime, index| {
                primesFe[index] = try utils.feFromBig(nMod, &prime);

                var primeMut = prime;
                defer primeMut.deinit();
            }

            var prikey: SecretKey = .{
                .public_key = .{
                    .n = nMod,
                    .e = eFe,
                },
                .d = dFe,
                .primes = try alloc.dupe(Fe, primesFe[0..]),
            };
            try prikey.precompute(alloc);

            const pubkey: PublicKey = .{
                .n = nMod,
                .e = eFe,
            };

            priv.public_key = pubkey;
            priv.secret_key = prikey;
            break;
        }

        return priv;
    }

    pub fn generateX931(alloc: Allocator, random: Random, bits: usize) !Self {
        if (bits < utils.min_modulus_bits or bits > utils.max_modulus_bits or bits % 2 != 0) {
            return error.RsaInvalidBits;
        }

        const e: u64 = 65537;

        const half = bits / 2;
        const half_len = utils.byteLen(half);

        var e_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &e_bytes, e, .big);

        var p_buf: [max_modulus_len]u8 = undefined;
        defer std.crypto.secureZero(u8, p_buf[0..half_len]);

        var q_buf: [max_modulus_len]u8 = undefined;
        defer std.crypto.secureZero(u8, q_buf[0..half_len]);

        const p_bytes = p_buf[0..half_len];
        const q_bytes = q_buf[0..half_len];

        var big4 = try utils.bigFromInt(alloc, 4);
        var big3 = try utils.bigFromInt(alloc, 3);

        defer big4.deinit();
        defer big3.deinit();

        while (true) {
            utils.generatePrime(random, half, e, p_bytes);
            while (true) {
                utils.generatePrime(random, half, e, q_bytes);
                if (!utils.topBitsMatch(p_bytes, q_bytes)) {
                    break;
                }
            }

            const pb = utils.stripLeadingZeros(p_bytes);
            const qb = utils.stripLeadingZeros(q_bytes);
            const eb = utils.stripLeadingZeros(&e_bytes);

            if (pb.len > max_modulus_len or qb.len > max_modulus_len) {
                continue;
            }

            // e must be odd and >= 3 (RFC 8017 §3.1); evenness would also fail the
            // gcd check below, but reject early and explicitly.
            if (eb.len == 0 or eb[eb.len - 1] & 1 == 0) {
                continue;
            }
            if (eb.len == 1 and eb[0] < 3) {
                continue;
            }

            var bp = try utils.bigFromBytes(alloc, pb);
            var bq = try utils.bigFromBytes(alloc, qb);
            var be = try utils.bigFromBytes(alloc, eb);

            defer bp.deinit();
            defer bq.deinit();
            defer be.deinit();

            // p == q
            if (bp.order(bq) == .eq) {
                continue;
            }

            // if prime % 4 == 3, it is true
            var prime_rem = try utils.bigMod(alloc, &bp, &big4);
            defer prime_rem.deinit();
            if (prime_rem.order(big3) != .eq) {
                continue;
            }

            var prime_rem2 = try utils.bigMod(alloc, &bq, &big4);
            defer prime_rem2.deinit();
            if (prime_rem2.order(big3) != .eq) {
                continue;
            }

            var bn = try utils.newBig(alloc);
            defer bn.deinit();
            try bn.mul(&bp, &bq);
            if (bn.bitCountAbs() > max_modulus_bits) {
                continue;
            }

            var n_buf: [max_modulus_len]u8 = undefined;
            bn.toConst().writeTwosComplement(&n_buf, .big);
            const n = Modulus.fromBytes(&n_buf, .big) catch {
                continue;
            };

            // λ(n) = lcm(p-1, q-1) = (p-1)(q-1) / gcd(p-1, q-1).
            var p1 = try utils.newBig(alloc);
            try p1.addScalar(&bp, -1);
            var q1 = try utils.newBig(alloc);
            try q1.addScalar(&bq, -1);
            var g = try utils.newBig(alloc);
            try g.gcd(&p1, &q1);
            var phi = try utils.newBig(alloc);
            try phi.mul(&p1, &q1);
            var lambda = try utils.newBig(alloc);
            var rem = try utils.newBig(alloc);
            try lambda.divFloor(&rem, &phi, &g); // exact: g | (p-1)(q-1)

            defer p1.deinit();
            defer q1.deinit();
            defer g.deinit();
            defer phi.deinit();
            defer lambda.deinit();
            defer rem.deinit();

            // d = e⁻¹ mod λ(n); also proves gcd(e, λ(n)) = 1.
            var bd = try utils.bigModInverse(alloc, &be, &lambda);
            if (bd.eqlZero()) {
                continue;
            }

            defer bd.deinit();

            const d = try utils.feFromBig(n, &bd);

            const fe_e = try Fe.fromBytes(n, &e_bytes, .big);
            const fe_p = try Fe.fromBytes(n, p_bytes, .big);
            const fe_q = try Fe.fromBytes(n, q_bytes, .big);

            const pk = PublicKey{
                .n = n,
                .e = fe_e,
            };

            var primes = [_]Fe{ fe_p, fe_q };

            var sk = SecretKey{
                .public_key = pk,
                .d = d,
                .primes = try alloc.dupe(Fe, primes[0..]),
            };
            try sk.precompute(alloc);

            return .{
                .public_key = pk,
                .secret_key = sk,
            };
        }
    }

    /// Return the public key corresponding to the secret key.
    pub fn fromSecretKey(secret_key: SecretKey) !Self {
        return .{
            .secret_key = secret_key,
            .public_key = secret_key.public_key,
        };
    }

    pub fn signPkcs1v15(self: Self, alloc: Allocator, comptime Hash: type, msg: []const u8) !PKCS1v15(Hash).Signature {
        var st = try self.signerPkcs1v15(alloc, Hash);
        st.update(msg);
        return st.finalize();
    }

    /// Sign a pre-hashed message using the key pair.
    /// The message must have already been hashed using the scheme's hash function.
    pub fn signPkcs1v15Prehashed(
        self: Self,
        alloc: Allocator,
        comptime Hash: type,
        msg_hash: [Hash.digest_length]u8,
    ) !PKCS1v15(Hash).Signature {
        var st = try self.signerPkcs1v15(alloc, Hash);
        return st.finalizePrehashed(msg_hash);
    }

    pub fn signerPkcs1v15(self: Self, alloc: Allocator, comptime Hash: type) !PKCS1v15(Hash).Signer {
        return PKCS1v15(Hash).Signer.init(alloc, self.secret_key);
    }

    pub fn signPss(
        self: Self,
        alloc: Allocator,
        random: Random,
        comptime Hash: type,
        msg: []const u8,
        opts: PSSOptions,
    ) !Pss(Hash).Signature {
        var st = try self.signerPss(alloc, random, Hash, opts);
        st.update(msg);
        return st.finalize();
    }

    /// Sign a pre-hashed message using the key pair.
    /// The message must have already been hashed using the scheme's hash function.
    pub fn signPssPrehashed(
        self: Self,
        alloc: Allocator,
        random: Random,
        comptime Hash: type,
        msg_hash: [Hash.digest_length]u8,
        opts: PSSOptions,
    ) !Pss(Hash).Signature {
        var st = try self.signerPss(alloc, random, Hash, opts);
        return st.finalizePrehashed(msg_hash);
    }

    /// Salt must outlive returned `PSS.Signer`.
    pub fn signerPss(
        self: Self,
        alloc: Allocator,
        random: Random,
        comptime Hash: type,
        opts: PSSOptions,
    ) !Pss(Hash).Signer {
        return Pss(Hash).Signer.init(alloc, random, self.secret_key, opts);
    }
};

const oid_rsa_publickey = "1.2.840.113549.1.1.1";

fn checkRSAPublickeyOid(oid: []const u8) !void {
    var buf: [256]u8 = undefined;
    var stream: std.Io.Writer = .fixed(&buf);
    try oids.decode(oid, &stream);

    const oid_string = stream.buffered();
    if (!std.mem.eql(u8, oid_string, oid_rsa_publickey)) {
        return error.RSAOidError;
    }

    return;
}

pub const Crypt = struct {
    const CryptT = @This();

    /// encrypt short plaintext with public key.
    pub fn encrypt(alloc: Allocator, public_key: PublicKey, plaintext: []const u8) ![]const u8 {
        const m = try Fe.fromBytes(public_key.n, plaintext, .big);
        const c = try public_key.n.powPublic(m, public_key.e);

        const k = public_key.size();

        const out = try alloc.alloc(u8, k);
        try c.toBytes(out, .big);

        return out;
    }

    /// decrypt short ciphertext with secret key.
    pub fn decrypt(alloc: Allocator, secret_key: SecretKey, ciphertext: []const u8, check: bool) ![]u8 {
        const n = secret_key.public_key.n;
        const k = secret_key.public_key.size();

        const c = try Fe.fromBytes(n, ciphertext, .big);
        const m = try n.pow(c, secret_key.d);

        const out = try alloc.alloc(u8, k);
        try m.toBytes(out, .big);

        if (check) {
            // In order to defend against errors in the CRT computation, m^e is
            // calculated, which should match the original ciphertext.
            const c2 = try n.powPublic(m, secret_key.public_key.e);
            if (!c.eql(c2)) {
                return error.RsaInternalError;
            }
        }

        return out;
    }

    pub fn decryptWithoutCheck(alloc: Allocator, secret_key: SecretKey, ciphertext: []const u8) ![]u8 {
        return CryptT.decrypt(alloc, secret_key, ciphertext, false);
    }

    pub fn decryptWithCheck(alloc: Allocator, secret_key: SecretKey, ciphertext: []const u8) ![]u8 {
        return CryptT.decrypt(alloc, secret_key, ciphertext, true);
    }

    pub fn encryptSecretKey(alloc: Allocator, secret_key: SecretKey, plaintext: []const u8, padding: Encrypter.RsaPadding) ![]const u8 {
        const n = secret_key.public_key.n;
        const m = try Fe.fromBytes(n, plaintext, .big);
        var c = try n.powPublic(m, secret_key.d);

        if (padding == .x931_padding) {
            var nn = try utils.bigFromModulus(alloc, n);
            var cc = try utils.bigFromFe(alloc, c);

            var f = try utils.newBig(alloc);
            try f.sub(&nn, &cc);

            defer nn.deinit();
            defer cc.deinit();
            defer f.deinit();

            if (f.order(cc) == .lt) {
                c = try utils.feFromBig(n, &f);
            }
        }

        const k = secret_key.public_key.size();

        const out = try alloc.alloc(u8, k);
        try c.toBytes(out, .big);

        return out;
    }

    pub fn decryptPublicKey(alloc: Allocator, public_key: PublicKey, ciphertext: []const u8, padding: Encrypter.RsaPadding) ![]u8 {
        const n = public_key.n;
        const k = public_key.size();

        const c = try Fe.fromBytes(n, ciphertext, .big);
        var m = try n.pow(c, public_key.e);

        var bigint15 = try utils.bigFromInt(alloc, 0xf);
        var mm = try utils.bigFromFe(alloc, m);

        var mLast4bit = try utils.newBig(alloc);
        try mLast4bit.bitAnd(&mm, &bigint15);

        defer bigint15.deinit();
        defer mm.deinit();
        defer mLast4bit.deinit();

        // it is true if (m & 0xf) != 12
        const mLast4bitInt = try mLast4bit.toInt(i32);
        if ((padding == .x931_padding) and (mLast4bitInt != 12)) {
            var nn = try utils.bigFromModulus(alloc, n);

            var f = try utils.newBig(alloc);
            try f.sub(&nn, &mm);

            defer nn.deinit();
            defer f.deinit();

            m = try utils.feFromBig(n, &f);
        }

        const out = try alloc.alloc(u8, k);
        try m.toBytes(out, .big);

        return out;
    }

    pub const Padding = struct {
        pub fn noPad(alloc: Allocator, em_len: usize, msg: []const u8) ![]const u8 {
            if (msg.len > em_len) {
                return error.RsaMsgTooLargeForKeySize;
            }
            if (msg.len < em_len) {
                return error.RsaMsgTooSmallForKeySize;
            }

            const out = try alloc.dupe(u8, msg);
            return out;
        }

        pub fn noUnpad(alloc: Allocator, k: usize, em: []const u8) ![]const u8 {
            if (k != em.len) {
                return error.RsaErrDecryption;
            }

            const out = try alloc.dupe(u8, em);
            return out;
        }

        pub fn pkcs1Type1Pad(alloc: Allocator, em_len: usize, msg: []const u8) ![]const u8 {
            if (msg.len > em_len - 11) {
                return error.RsaMessageTooLong;
            }

            // EM = 0x00 || 0x01 || PS || 0x00 || M.
            var em = try alloc.alloc(u8, em_len);

            em[0] = 0;
            em[1] = 1;

            const ps = em[2..][0 .. em_len - msg.len - 3];

            @memset(ps[0..], 0xff);

            em[em.len - msg.len - 1] = 0;
            @memcpy(em[em.len - msg.len ..][0..msg.len], msg);

            return em;
        }

        pub fn pkcs1Type1Unpad(alloc: Allocator, k: usize, em: []const u8) ![]const u8 {
            if (k < 11) {
                return error.RsaErrDecryption;
            }

            if (ct.@"or"(em[0] != 0, ct.@"and"(em[1] != 0, em[1] != 1))) {
                return error.RsaInconsistent;
            }

            var i: usize = 2;
            while (i < em.len) {
                if (em[i] != 0xff) {
                    if (em[i] == 0) {
                        break;
                    }
                }

                i += 1;
            }

            i += 1;

            if (i == em.len) {
                return &[_]u8{};
            }

            if (i - 1 < 8) {
                return error.RsaInconsistent;
            }

            const out = try alloc.dupe(u8, em[i..]);
            return out;
        }

        pub fn pkcs1Type2Pad(alloc: Allocator, random: Random, em_len: usize, msg: []const u8) ![]const u8 {
            if (msg.len > em_len - 11) {
                return error.RsaMessageTooLong;
            }

            // EM = 0x00 || 0x02 || PS || 0x00 || M.
            var em = try alloc.alloc(u8, em_len);

            em[0] = 0;
            em[1] = 2;

            const ps = em[2..][0 .. em_len - msg.len - 3];

            // Section: 7.2.1
            // PS consists of pseudo-randomly generated nonzero octets.
            for (ps) |*v| {
                v.* = random.uintLessThan(u8, 0xff) + 1;
            }

            em[em.len - msg.len - 1] = 0;
            @memcpy(em[em.len - msg.len ..][0..msg.len], msg);

            return em;
        }

        pub fn pkcs1Type2Unpad(alloc: Allocator, k: usize, em: []const u8) ![]const u8 {
            if (k < 11) {
                return error.RsaErrDecryption;
            }

            // Care shall be taken to ensure that an opponent cannot
            // distinguish these error conditions, whether by error
            // message or timing.
            const msg_start = ct.lastIndexOfScalar(em, 0) orelse em.len;
            const ps_len = em.len - msg_start;
            if (ct.@"or"(em[0] != 0, ct.@"or"(em[1] != 2, ps_len < 8))) {
                return error.RsaInconsistent;
            }

            const out = try alloc.dupe(u8, em[msg_start + 1 ..]);
            return out;
        }

        pub fn oaepPad(
            alloc: Allocator,
            random: Random,
            comptime Hash: type,
            comptime MgfHash: type,
            em_len: usize,
            msg: []const u8,
            label: []const u8,
        ) ![]const u8 {
            const hash_size = Hash.digest_length;

            if (msg.len > em_len - 2 * hash_size - 2) {
                return error.RsaMessageTooLong;
            }

            // EM = 0x00 || maskedSeed || maskedDB.
            var em = try alloc.alloc(u8, em_len);

            em[0] = 0;
            const seed = em[1..][0..hash_size];

            random.bytes(seed);

            // DB = lHash || PS || 0x01 || M.
            var db = em[1 + seed.len ..];
            const lHash = oaepLabelHash(Hash, label);
            @memcpy(db[0..lHash.len], lHash);
            @memset(db[lHash.len .. db.len - msg.len - 2], 0);
            db[db.len - msg.len - 1] = 1;
            @memcpy(db[db.len - msg.len ..][0..msg.len], msg);

            mgf1XOR(MgfHash, seed, db);
            mgf1XOR(MgfHash, db, seed);

            return em;
        }

        pub fn oaepUnpad(
            alloc: Allocator,
            comptime Hash: type,
            comptime MgfHash: type,
            em_bytes: []const u8,
            label: []const u8,
        ) ![]u8 {
            const hash_size = Hash.digest_length;

            var em = try alloc.alloc(u8, em_bytes.len);
            defer alloc.free(em);

            @memcpy(em[0..], em_bytes[0..]);

            const y = em[0];
            const seed = em[1..][0..hash_size];
            const db = em[1 + hash_size ..];

            mgf1XOR(MgfHash, db, seed);
            mgf1XOR(MgfHash, seed, db);

            const expected_hash = oaepLabelHash(Hash, label);
            const actual_hash = db[0..expected_hash.len];

            // Care shall be taken to ensure that an opponent cannot
            // distinguish these error conditions, whether by error
            // message or timing.
            const msg_start = ct.indexOfScalarPos(em, expected_hash.len + 1, 1) orelse 0;
            if (ct.@"or"(y != 0, ct.@"or"(msg_start == 0, !ct.memEql(expected_hash, actual_hash)))) {
                return error.RsaInconsistent;
            }

            const out = try alloc.dupe(u8, em[msg_start + 1 ..]);
            return out;
        }

        inline fn oaepLabelHash(comptime HashType: type, label: []const u8) []const u8 {
            if (label.len == 0) {
                // magic constants from NIST
                switch (HashType) {
                    std.crypto.hash.Sha1 => return &.{
                        0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d,
                        0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90,
                        0xaf, 0xd8, 0x07, 0x09,
                    },
                    sha2.Sha256 => return &.{
                        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
                        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
                        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
                        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
                    },
                    sha2.Sha384 => return &.{
                        0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38,
                        0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a,
                        0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43,
                        0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda,
                        0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb,
                        0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b,
                    },
                    sha2.Sha512 => return &.{
                        0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
                        0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
                        0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
                        0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
                        0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
                        0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
                        0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
                        0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
                    },
                    else => {},
                }
            }

            var res: [HashType.digest_length]u8 = undefined;
            HashType.hash(label, &res, .{});
            return res[0..];
        }

        pub fn x931Pad(alloc: Allocator, em_len: usize, msg: []const u8) ![]const u8 {
            var em = try alloc.alloc(u8, em_len);

            const j = em_len - msg.len - 2;
            if (j < 0) {
                return error.RsaMsgTooLarge;
            }

            if (j == 0) {
                em[0] = 0x6a;
            } else {
                em[0] = 0x6b;
                if (j > 1) {
                    @memset(em[1..j], 0xbb);
                }
                em[j] = 0xba;
            }

            @memcpy(em[em.len - msg.len - 1 ..][0..msg.len], msg);
            em[em.len - 1] = 0xcc;

            return em;
        }

        pub fn x931Unpad(alloc: Allocator, k: usize, em: []const u8) ![]const u8 {
            if (k < 2) {
                return error.RsaErrDecryption;
            }

            var i: usize = 0;
            var j: usize = 0;

            if (em[0] != 0x6a and em[0] != 0x6b) {
                return error.RsaInvalidHeader;
            }

            if (em[0] == 0x6b) {
                j = em.len - 3;

                i = 0;
                while (i < j) : (i += 1) {
                    if (em[i + 1] == 0xba) {
                        break;
                    }

                    if (em[i + 1] != 0xbb) {
                        return error.RsaInvalidPadding;
                    }
                }

                j -= i;
            } else {
                j = em.len - 2;
            }

            if (em[em.len - 1] != 0xcc) {
                return error.RsaInvalidTrailer;
            }

            const out = try alloc.dupe(u8, em[em.len - j - 1 .. em.len - 1]);
            return out;
        }
    };

    pub const Encrypter = struct {
        alloc: Allocator,

        // encrypter padding type
        padding: RsaPadding = .pkcs1_padding,

        // encrypter for pkcs1Type2Pad, oaepPad
        random: Random = undefined,

        const Self = @This();

        pub const RsaPadding = enum {
            pkcs1_padding,
            oaep_padding,
            x931_padding,
            no_padding,
        };

        pub fn init(alloc: Allocator) Self {
            return .{
                .alloc = alloc,
            };
        }

        pub fn withPadding(self: *Self, padding: RsaPadding) void {
            self.padding = padding;
        }

        pub fn withRandom(self: *Self, random: Random) void {
            self.random = random;
        }

        pub fn encrypt(self: *Self, public_key: PublicKey, msg: []const u8) ![]const u8 {
            // align variable names with spec
            const k = public_key.size();

            const em = switch (self.padding) {
                .pkcs1_padding => try Padding.pkcs1Type2Pad(self.alloc, self.random, k, msg),
                .no_padding => try Padding.noPad(self.alloc, k, msg),
                else => {
                    return error.RsaPaddingNotSupport;
                },
            };
            defer self.alloc.free(em);

            const out = try CryptT.encrypt(self.alloc, public_key, em);
            return out;
        }

        pub fn decrypt(self: *Self, secret_key: SecretKey, ciphertext: []const u8) ![]const u8 {
            const em = try CryptT.decryptWithoutCheck(self.alloc, secret_key, ciphertext);
            defer self.alloc.free(em);

            const k = secret_key.public_key.size();

            const out = switch (self.padding) {
                .pkcs1_padding => try Padding.pkcs1Type2Unpad(self.alloc, k, em),
                .no_padding => try Padding.noUnpad(self.alloc, k, em),
                else => {
                    return error.RsaPaddingNotSupport;
                },
            };
            return out;
        }

        pub fn encryptSecretKey(self: *Self, secret_key: SecretKey, msg: []const u8) ![]const u8 {
            const k = secret_key.public_key.size();

            const em = switch (self.padding) {
                .pkcs1_padding => try Padding.pkcs1Type1Pad(self.alloc, k, msg),
                .x931_padding => try Padding.x931Pad(self.alloc, k, msg),
                .no_padding => try Padding.noPad(self.alloc, k, msg),
                else => {
                    return error.RsaPaddingNotSupport;
                },
            };
            defer self.alloc.free(em);

            const out = try CryptT.encryptSecretKey(self.alloc, secret_key, em, self.padding);
            return out;
        }

        pub fn decryptPublicKey(self: *Self, public_key: PublicKey, ciphertext: []const u8) ![]const u8 {
            const em = try CryptT.decryptPublicKey(self.alloc, public_key, ciphertext, self.padding);
            defer self.alloc.free(em);

            const k = public_key.size();

            const out = switch (self.padding) {
                .pkcs1_padding => try Padding.pkcs1Type1Unpad(self.alloc, k, em),
                .x931_padding => try Padding.x931Unpad(self.alloc, k, em),
                .no_padding => try Padding.noUnpad(self.alloc, k, em),
                else => {
                    return error.RsaPaddingNotSupport;
                },
            };
            return out;
        }
    };

    pub const Pkcs1v15 = struct {
        /// encrypt a short message using RSAES-PKCS1-v1_5.
        pub fn encrypt(alloc: Allocator, random: Random, public_key: PublicKey, msg: []const u8) ![]const u8 {
            var encrypter = CryptT.Encrypter.init(alloc);
            encrypter.withRandom(random);
            encrypter.withPadding(.pkcs1_padding);

            const out = try encrypter.encrypt(public_key, msg);
            return out;
        }

        /// decrypt a encrtpted message using RSAES-PKCS1-v1_5.
        pub fn decrypt(alloc: Allocator, secret_key: SecretKey, ciphertext: []const u8) ![]const u8 {
            var encrypter = CryptT.Encrypter.init(alloc);
            encrypter.withPadding(.pkcs1_padding);

            const out = try encrypter.decrypt(secret_key, ciphertext);
            return out;
        }

        /// encryptSecretKey a short message using RSAES-PKCS1-v1_5.
        pub fn encryptSecretKey(alloc: Allocator, secret_key: SecretKey, msg: []const u8) ![]const u8 {
            var encrypter = CryptT.Encrypter.init(alloc);
            encrypter.withPadding(.pkcs1_padding);

            const out = try encrypter.encryptSecretKey(secret_key, msg);
            return out;
        }

        /// decryptPublicKey a encrtpted message using RSAES-PKCS1-v1_5.
        pub fn decryptPublicKey(alloc: Allocator, public_key: PublicKey, ciphertext: []const u8) ![]const u8 {
            var encrypter = CryptT.Encrypter.init(alloc);
            encrypter.withPadding(.pkcs1_padding);

            const out = try encrypter.decryptPublicKey(public_key, ciphertext);
            return out;
        }
    };

    pub const Oaep = struct {
        const Self = @This();

        // Options corresponds to options for OAEP decryption.
        pub const Options = struct {
            // hash is the hash function that will be used when generating the mask.
            hash: type,

            // mgf_hash is the hash function used for MGF1.
            mgf_hash: ?type = null,

            // label is an arbitrary byte string that must be equal to the value
            // used when encrypting.
            label: []const u8 = "",
        };

        /// Encrypt a short message using Optimal Asymmetric Encryption Padding (RSAES-OAEP).
        pub fn encrypt(
            alloc: Allocator,
            random: Random,
            public_key: PublicKey,
            comptime Hash: type,
            msg: []const u8,
            label: []const u8,
        ) ![]const u8 {
            return Self.encryptInternal(alloc, random, public_key, Hash, Hash, msg, label);
        }

        pub fn decrypt(
            alloc: Allocator,
            secret_key: SecretKey,
            comptime Hash: type,
            ciphertext: []const u8,
            label: []const u8,
        ) ![]u8 {
            return Self.decryptInternal(alloc, secret_key, Hash, Hash, ciphertext, label);
        }

        pub fn encryptWithOptions(
            alloc: Allocator,
            random: Random,
            public_key: PublicKey,
            msg: []const u8,
            opts: Options,
        ) ![]const u8 {
            if (opts.mgf_hash) |mgf_hash| {
                return Self.encryptInternal(alloc, random, public_key, opts.hash, mgf_hash, msg, opts.label);
            }

            return Self.encryptInternal(alloc, random, public_key, opts.hash, opts.hash, msg, opts.label);
        }

        pub fn decryptWithOptions(
            alloc: Allocator,
            secret_key: SecretKey,
            ciphertext: []const u8,
            opts: Options,
        ) ![]u8 {
            if (opts.mgf_hash) |mgf_hash| {
                return Self.decryptInternal(alloc, secret_key, opts.hash, mgf_hash, ciphertext, opts.label);
            }

            return Self.decryptInternal(alloc, secret_key, opts.hash, opts.hash, ciphertext, opts.label);
        }

        /// Encrypt a short message using Optimal Asymmetric Encryption Padding (RSAES-OAEP).
        fn encryptInternal(
            alloc: Allocator,
            random: Random,
            public_key: PublicKey,
            comptime Hash: type,
            comptime MgfHash: type,
            msg: []const u8,
            label: []const u8,
        ) ![]const u8 {
            // align variable names with spec
            const k = public_key.size();

            const hash_size = Hash.digest_length;
            if (msg.len > k - 2 * hash_size - 2) {
                return error.RsaMessageTooLong;
            }

            const em = try CryptT.Padding.oaepPad(alloc, random, Hash, MgfHash, k, msg, label);
            defer alloc.free(em);

            const out = try CryptT.encrypt(alloc, public_key, em);
            return out;
        }

        fn decryptInternal(
            alloc: Allocator,
            secret_key: SecretKey,
            comptime Hash: type,
            comptime MgfHash: type,
            ciphertext: []const u8,
            label: []const u8,
        ) ![]u8 {
            const k = secret_key.public_key.size();
            const hash_size = Hash.digest_length;
            if (ciphertext.len > k or k < (hash_size * 2 + 2)) {
                return error.RsaErrDecryption;
            }

            const em = try CryptT.decryptWithoutCheck(alloc, secret_key, ciphertext);
            defer alloc.free(em);

            const out = try CryptT.Padding.oaepUnpad(alloc, Hash, MgfHash, em, label);
            return out;
        }
    };
};

/// Signature Scheme with Appendix v1.5 (RSASSA-PKCS1-v1_5)
pub fn PKCS1v15(comptime H: type) type {
    return struct {
        const PkcsT = @This();

        pub const Hash = H;

        pub const Signature = struct {
            bytes: []u8,

            const Self = @This();

            pub fn deinit(self: *Self, alloc: Allocator) void {
                alloc.free(self.bytes);
            }

            pub fn verifier(self: Self, alloc: Allocator, public_key: PublicKey) !PkcsT.Verifier {
                return Verifier.init(alloc, self, public_key);
            }

            pub fn verify(self: Self, alloc: Allocator, msg: []const u8, public_key: PublicKey) !void {
                var st = Verifier.init(alloc, self, public_key);
                st.update(msg);
                return st.verify();
            }

            /// Verify the signature against a pre-hashed message and public key.
            /// The message must have already been hashed using the scheme's hash function.
            pub fn verifyPrehashed(self: Self, alloc: Allocator, msg_hash: [Hash.digest_length]u8, public_key: PublicKey) !void {
                var st = try self.verifier(alloc, public_key);
                return st.verifyPrehashed(msg_hash);
            }

            /// Return the raw signature bytes.
            pub fn toBytes(self: Self) []u8 {
                return self.bytes;
            }

            /// Create a signature from a bytes.
            pub fn fromBytes(bytes: []u8) Self {
                return .{
                    .bytes = bytes,
                };
            }
        };

        pub const Signer = struct {
            alloc: Allocator,
            h: Hash,
            secret_key: SecretKey,

            const Self = @This();

            pub fn init(alloc: Allocator, secret_key: SecretKey) Self {
                return .{
                    .alloc = alloc,
                    .h = Hash.init(.{}),
                    .secret_key = secret_key,
                };
            }

            pub fn update(self: *Self, data: []const u8) void {
                self.h.update(data);
            }

            fn finalizePrehashed(self: *Self, msg_hash: [Hash.digest_length]u8) !PkcsT.Signature {
                const pk = self.secret_key.public_key;
                const k = pk.size();

                const prefix = comptime PkcsT.hashPrefixe(Hash);

                const em = try PkcsT.emsaEncode(self.alloc, &msg_hash, k, prefix);
                defer self.alloc.free(em);

                const sig = try Crypt.decryptWithCheck(self.alloc, self.secret_key, em);

                const siged = PkcsT.Signature.fromBytes(sig);
                return siged;
            }

            pub fn finalize(self: *Self) !PkcsT.Signature {
                var hashed: [Hash.digest_length]u8 = undefined;
                self.h.final(&hashed);
                const sig = self.finalizePrehashed(hashed);
                return sig;
            }
        };

        pub const Verifier = struct {
            alloc: Allocator,
            h: Hash,
            sig: []u8,
            public_key: PublicKey,

            const Self = @This();

            fn init(alloc: Allocator, sig: PkcsT.Signature, public_key: PublicKey) Self {
                return .{
                    .alloc = alloc,
                    .h = Hash.init(.{}),
                    .sig = sig.bytes,
                    .public_key = public_key,
                };
            }

            pub fn update(self: *Self, data: []const u8) void {
                self.h.update(data);
            }

            fn verifyPrehashed(self: *Self, msg_hash: [Hash.digest_length]u8) !void {
                const pk = self.public_key;
                const k = pk.size();

                const em = try Crypt.encrypt(self.alloc, pk, self.sig);
                defer self.alloc.free(em);

                const prefix = comptime PkcsT.hashPrefixe(Hash);

                const expected = try PkcsT.emsaEncode(self.alloc, &msg_hash, k, prefix);
                defer self.alloc.free(expected);

                if (!std.mem.eql(u8, expected, em)) {
                    return error.RsaVerifyFail;
                }
            }

            pub fn verify(self: *Self) !void {
                var hashed: [Hash.digest_length]u8 = undefined;
                self.h.final(&hashed);
                try self.verifyPrehashed(hashed);
            }
        };

        /// sign with no hash msg
        pub fn signPlain(alloc: Allocator, secret_key: SecretKey, msg: []const u8) ![]u8 {
            const pk = secret_key.public_key;

            const k = pk.size();

            const em = try PkcsT.emsaEncode(alloc, msg, k, &[_]u8{});
            defer alloc.free(em);

            const sig = try Crypt.decryptWithCheck(alloc, secret_key, em);
            return sig;
        }

        pub fn verifyPlain(alloc: Allocator, public_key: PublicKey, msg: []const u8, sig: []u8) !void {
            const em = try Crypt.encrypt(alloc, public_key, sig);
            defer alloc.free(em);

            const k = public_key.size();

            const expected = try PkcsT.emsaEncode(alloc, msg, k, &[_]u8{});
            defer alloc.free(expected);

            if (!std.mem.eql(u8, expected, em)) {
                return error.RsaVerifyFail;
            }
        }

        /// PKCS Encrypted Message Signature Appendix
        fn emsaEncode(alloc: Allocator, m_hash: []const u8, em_len: usize, prefix: []const u8) ![]u8 {
            if (em_len < prefix.len + m_hash.len + 2 + 8 + 1) {
                return error.RsaMessageTooLong;
            }

            var em = try alloc.alloc(u8, em_len);
            em[0] = 0;
            em[1] = 1;
            const padding_len = em_len - prefix.len - m_hash.len - 3;
            @memset(em[2..][0..padding_len], 0xff);
            em[2 + padding_len] = 0;
            @memcpy(em[em_len - prefix.len - m_hash.len ..][0..prefix.len], prefix);
            @memcpy(em[em_len - m_hash.len ..][0..m_hash.len], m_hash);

            return em;
        }

        /// DER encoded header. Sequence of digest algo + digest.
        fn hashPrefixe(HashType: type) []const u8 {
            // Section 9.2 Notes 1.
            return &switch (HashType) {
                std.crypto.hash.Md5 => .{
                    0x30, 0x20, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86,
                    0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05, 0x05, 0x00,
                    0x04, 0x10,
                },
                std.crypto.hash.Sha1 => .{
                    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
                    0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
                },
                sha2.Sha224 => .{
                    0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
                    0x00, 0x04, 0x1c,
                },
                sha2.Sha256 => .{
                    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
                    0x00, 0x04, 0x20,
                },
                sha2.Sha384 => .{
                    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
                    0x00, 0x04, 0x30,
                },
                sha2.Sha512 => .{
                    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
                    0x00, 0x04, 0x40,
                },
                sha2.Sha512_224 => .{
                    0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05, 0x05,
                    0x00, 0x04, 0x1C,
                },
                sha2.Sha512_256 => .{
                    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06, 0x05,
                    0x00, 0x04, 0x20,
                },
                sha3.Sha3_224 => .{
                    0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07, 0x05,
                    0x00, 0x04, 0x1C,
                },
                sha3.Sha3_256 => .{
                    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08, 0x05,
                    0x00, 0x04, 0x20,
                },
                sha3.Sha3_384 => .{
                    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09, 0x05,
                    0x00, 0x04, 0x30,
                },
                sha3.Sha3_512 => .{
                    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a, 0x05,
                    0x00, 0x04, 0x40,
                },
                // hash.ripemd160 => .{
                //     0x30, 0x20, 0x30, 0x08, 0x06, 0x06, 0x28, 0xcf,
                //     0x06, 0x03, 0x00, 0x31, 0x04, 0x14,
                // },
                // sm3.SM3 => .{
                //     0x30, 0x30, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x81,
                //     0x1c, 0xcf, 0x55, 0x01, 0x83, 0x78, 0x05, 0x00,
                //     0x04, 0x20,
                // },
                else => @compileError("unknown Hash " ++ @typeName(Hash)),
            };
        }
    };
}

// pss_salt_length_auto causes the salt in a PSS signature to be as large
// as possible when signing, and to be auto-detected when verifying.
pub const pss_salt_length_auto = 0;

// pss_salt_length_equals_hash causes the salt length to equal the length
// of the hash used in the signature.
pub const pss_salt_length_equals_hash = -1;

// PSSOptions contains options for creating and verifying PSS signatures.
pub const PSSOptions = struct {
    // SaltLength controls the length of the salt used in the PSS
    // signature. It can either be a number of bytes, or one of the special
    // pss_salt_length constants.
    salt_leng: isize = 0,

    // if salt set, and will use it
    salt: ?[]const u8 = null,
};

/// Probabilistic Signature Scheme (RSASSA-PSS)
pub fn Pss(comptime H: type) type {
    return struct {
        const PssT = @This();

        pub const Hash = H;

        pub const Signature = struct {
            bytes: []u8,

            const Self = @This();

            pub fn deinit(self: *Self, alloc: Allocator) void {
                alloc.free(self.bytes);
            }

            pub fn verifier(self: Self, alloc: Allocator, public_key: PublicKey, opts: PSSOptions) !PssT.Verifier {
                return Verifier.init(alloc, self, public_key, opts);
            }

            pub fn verify(self: Self, alloc: Allocator, msg: []const u8, public_key: PublicKey, opts: PSSOptions) !void {
                var st = Verifier.init(alloc, self, public_key, opts);
                st.update(msg);
                return st.verify();
            }

            /// Verify the signature against a pre-hashed message and public key.
            /// The message must have already been hashed using the scheme's hash function.
            pub fn verifyPrehashed(self: Self, alloc: Allocator, msg_hash: [Hash.digest_length]u8, public_key: PublicKey, opts: PSSOptions) !void {
                var st = try self.verifier(alloc, public_key, opts);
                return st.verifyPrehashed(msg_hash);
            }

            /// Return the raw signature bytes.
            pub fn toBytes(self: Self) []u8 {
                return self.bytes;
            }

            /// Create a signature from a bytes.
            pub fn fromBytes(bytes: []u8) Self {
                return .{
                    .bytes = bytes,
                };
            }
        };

        pub const Signer = struct {
            alloc: Allocator,
            random: Random,
            h: Hash,
            secret_key: SecretKey,
            opts: PSSOptions,

            const Self = @This();

            pub fn init(alloc: Allocator, random: Random, secret_key: SecretKey, opts: PSSOptions) Self {
                return .{
                    .alloc = alloc,
                    .random = random,
                    .h = Hash.init(.{}),
                    .secret_key = secret_key,
                    .opts = opts,
                };
            }

            pub fn update(self: *Self, data: []const u8) void {
                self.h.update(data);
            }

            fn finalizePrehashed(self: *Self, msg_hash: [Hash.digest_length]u8) !PssT.Signature {
                const hash_size = Hash.digest_length;
                const n = self.secret_key.public_key.n;

                // RFC 4055 S3.1
                const salt = if (self.opts.salt) |s| brk1: {
                    const res = try self.alloc.dupe(u8, s);
                    break :brk1 res;
                } else brk: {
                    var salt_len: usize = 0;
                    switch (self.opts.salt_leng) {
                        pss_salt_length_auto => {
                            salt_len = (n.bits() - 1 + 7) / 8 - 2 - hash_size;
                        },
                        pss_salt_length_equals_hash => {
                            salt_len = hash_size;
                        },
                        else => {
                            if (self.opts.salt_leng > 0) {
                                salt_len = @as(usize, @intCast(self.opts.salt_leng));
                            }
                        },
                    }

                    const res = try self.alloc.alloc(u8, salt_len);

                    self.random.bytes(res);
                    break :brk res;
                };

                const em_bits = n.bits() - 1;
                const em = try PssT.emsaPSSEncode(self.alloc, &msg_hash, em_bits, salt, Hash);

                defer self.alloc.free(salt);
                defer self.alloc.free(em);

                const k = self.secret_key.public_key.size();
                if (em.len > k) {
                    return error.RsaMessageTooLong;
                }

                const sig = try Crypt.decryptWithCheck(self.alloc, self.secret_key, em);

                const siged = PssT.Signature.fromBytes(sig);
                return siged;
            }

            pub fn finalize(self: *Self) !PssT.Signature {
                var hashed: [Hash.digest_length]u8 = undefined;
                self.h.final(&hashed);

                const sig = try self.finalizePrehashed(hashed);
                return sig;
            }
        };

        pub const Verifier = struct {
            alloc: Allocator,
            h: Hash,
            sig: []u8,
            public_key: PublicKey,
            salt_len: usize,

            const Self = @This();

            fn init(alloc: Allocator, sig: PssT.Signature, public_key: PublicKey, opts: PSSOptions) Self {
                var salt_len: usize = 0;
                switch (opts.salt_leng) {
                    pss_salt_length_equals_hash => {
                        salt_len = Hash.digest_length;
                    },
                    else => {
                        if (opts.salt_leng > 0) {
                            salt_len = @as(usize, @intCast(opts.salt_leng));
                        }
                    },
                }

                return .{
                    .alloc = alloc,
                    .h = Hash.init(.{}),
                    .sig = sig.bytes,
                    .public_key = public_key,
                    .salt_len = salt_len,
                };
            }

            pub fn update(self: *Self, data: []const u8) void {
                self.h.update(data);
            }

            fn verifyPrehashed(self: *Self, msg_hash: [Hash.digest_length]u8) !void {
                const pk = self.public_key;
                const encrypted = try Crypt.encrypt(self.alloc, pk, self.sig);
                defer self.alloc.free(encrypted);

                var em = try self.alloc.alloc(u8, encrypted.len);
                defer self.alloc.free(em);

                @memcpy(em[0..], encrypted[0..]);

                const mod_bits = pk.n.bits();
                try PssT.emsaPSSVerify(&msg_hash, em, mod_bits - 1, self.salt_len, Hash);
            }

            pub fn verify(self: *Self) !void {
                var hashed: [Hash.digest_length]u8 = undefined;
                self.h.final(&hashed);
                try self.verifyPrehashed(hashed);
            }
        };

        /// PSS Encrypted Message Signature Appendix
        fn emsaPSSEncode(alloc: Allocator, msg_hash: []const u8, em_bits: usize, salt: []const u8, HashType: type) ![]u8 {
            // See RFC 8017, Section 9.1.1.

            // emLen = \ceil(emBits/8)
            const em_len = (em_bits + 7) / 8;
            const s_len = salt.len;
            const h_len = HashType.digest_length;

            // 1.  If the length of M is greater than the input limitation for the
            //     hash function (2^61 - 1 octets for SHA-1), output "message too
            //     long" and stop.
            //
            // 2.  Let mHash = Hash(M), an octet string of length hLen.

            if (msg_hash.len != h_len) {
                return error.RsaInputLongthError;
            }

            // 3.  If emLen < hLen + sLen + 2, output "encoding error" and stop.
            if (em_len < h_len + s_len + 2) {
                return error.RsaMsgTooLong;
            }

            // EM = maskedDB || H || 0xbc
            var em = try alloc.alloc(u8, em_len);
            const ps_len = em_len - s_len - h_len - 2;
            var db = em[0 .. ps_len + 1 + s_len];
            const hashed = em[ps_len + 1 + s_len ..][0..h_len];

            // 4.  Generate a random octet string salt of length sLen; if sLen = 0,
            //     then salt is the empty string.
            //
            // 5.  Let
            //       M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;
            //
            //     M' is an octet string of length 8 + hLen + sLen with eight
            //     initial zero octets.
            //
            // 6.  Let H = Hash(M'), an octet string of length hLen.

            var hasher = HashType.init(.{});
            hasher.update(&([_]u8{0} ** 8));
            hasher.update(msg_hash);
            hasher.update(salt);
            hasher.final(hashed);

            // DB = PS || 0x01 || salt
            @memset(db[0..ps_len], 0);

            // 7.  Generate an octet string PS consisting of emLen - sLen - hLen - 2
            //     zero octets. The length of PS may be 0.
            //
            // 8.  Let DB = PS || 0x01 || salt; DB is an octet string of length
            //     emLen - hLen - 1.

            db[ps_len] = 1;
            @memcpy(db[ps_len + 1 ..], salt);

            // 9.  Let dbMask = MGF(H, emLen - hLen - 1).
            //
            // 10. Let maskedDB = DB \xor dbMask.

            mgf1XOR(HashType, hashed, db);

            // 11. Set the leftmost 8 * emLen - emBits bits of the leftmost octet in
            //     maskedDB to zero.
            const shift = std.math.comptimeMod(8 * em_len - em_bits, 8);
            const mask = @as(u8, 0xff) >> shift;
            db[0] &= mask;

            // 12. Let EM = maskedDB || H || 0xbc.
            em[em.len - 1] = 0xbc;

            return em;
        }

        fn emsaPSSVerify(m_hash: []const u8, em: []u8, em_bits: usize, slen: usize, HashType: type) !void {
            const hlen = HashType.digest_length;

            var s_len = slen;
            if (slen == pss_salt_length_equals_hash) {
                s_len = hlen;
            }

            // 1.   If the length of M is greater than the input limitation for
            //      the hash function (2^61 - 1 octets for SHA-1), output
            //      "inconsistent" and stop.
            // All the cryptographic hash functions in the standard library have a limit of >= 2^61 - 1.
            // Even then, this check is only there for paranoia. In the context of TLS certificates, emBit cannot exceed 4096.
            if (em_bits >= 1 << 61) {
                return error.RsaInvalidSignature;
            }

            // emLen = \ceil(emBits/8)
            const em_len = (em_bits + 7) / 8;
            if (em_len != em.len) {
                return error.RsaInconsistentLength;
            }

            // 2.   Let mHash = Hash(M), an octet string of length hLen.
            if (hlen != m_hash.len) {
                return error.RsaInvalidSignature;
            }

            // 3.   If emLen < hLen + sLen + 2, output "inconsistent" and stop.
            if (em_len < hlen + s_len + 2) {
                return error.RsaInvalidSignature;
            }

            // 4.   If the rightmost octet of EM does not have hexadecimal value
            //      0xbc, output "inconsistent" and stop.
            if (em[em.len - 1] != 0xbc) {
                return error.RsaInvalidSignature;
            }

            // 5.   Let maskedDB be the leftmost emLen - hLen - 1 octets of EM,
            //      and let H be the next hLen octets.
            var db = em[0..(em_len - hlen - 1)];
            const h = em[(em_len - hlen - 1)..][0..hlen];

            // 6.   If the leftmost 8emLen - emBits bits of the leftmost octet in
            //      maskedDB are not all equal to zero, output "inconsistent" and
            //      stop.
            const shift = std.math.comptimeMod(8 * em_len - em_bits, 8);
            const bitMask = @as(u8, 0xff) >> shift;
            if ((em[0] & ~bitMask) != 0) {
                return error.RsaInvalidSignature;
            }

            // 7.  Let dbMask = MGF(H, emLen - hLen - 1).
            //
            // 8.  Let DB = maskedDB \xor dbMask.

            mgf1XOR(HashType, h, db);

            // 9.   Set the leftmost 8emLen - emBits bits of the leftmost octet
            //      in DB to zero.
            db[0] &= bitMask;

            if (s_len == pss_salt_length_auto) {
                if (std.mem.indexOfScalar(u8, db, 0x01)) |ps_len| {
                    s_len = db.len - ps_len - 1;
                } else {
                    return error.RsaErrorVerification;
                }
            }

            // 10.  If the emLen - hLen - sLen - 2 leftmost octets of DB are not
            //      zero or if the octet at position emLen - hLen - sLen - 1 (the
            //      leftmost position is "position 1") does not have hexadecimal
            //      value 0x01, output "inconsistent" and stop.
            const ps_len = em_len - hlen - s_len - 2;
            for (db[0..ps_len]) |e| {
                if (e != 0x00) {
                    return error.RsaInvalidSignature;
                }
            }

            if (db[ps_len] != 0x01) {
                return error.RsaInvalidSignature;
            }

            // 11.  Let salt be the last sLen octets of DB.
            const salt = db[(db.len - s_len)..];

            // 12.  Let
            //         M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt ;
            //      M' is an octet string of length 8 + hLen + sLen with eight
            //      initial zero octets.
            // 13.  Let H' = Hash(M'), an octet string of length hLen.
            var h_p: [hlen]u8 = undefined;
            var hasher = HashType.init(.{});
            hasher.update(&([_]u8{0} ** 8));
            hasher.update(m_hash);
            hasher.update(salt);
            hasher.final(&h_p);

            // 14.  If H = H', output "consistent".  Otherwise, output
            //      "inconsistent".
            if (!std.mem.eql(u8, h, &h_p)) {
                return error.RsaInvalidSignature;
            }
        }
    };
}

/// Signature Scheme with X931
pub fn X931(comptime H: type) type {
    return struct {
        const X931T = @This();

        pub const Hash = H;

        pub const Signature = struct {
            bytes: []u8,

            const Self = @This();

            pub fn deinit(self: *Self, alloc: Allocator) void {
                alloc.free(self.bytes);
            }

            pub fn verifier(self: Self, alloc: Allocator, public_key: PublicKey) !X931T.Verifier {
                return Verifier.init(alloc, self, public_key);
            }

            pub fn verify(self: Self, alloc: Allocator, msg: []const u8, public_key: PublicKey) !void {
                var st = Verifier.init(alloc, self, public_key);
                st.update(msg);
                return st.verify();
            }

            /// Verify the signature against a pre-hashed message and public key.
            /// The message must have already been hashed using the scheme's hash function.
            pub fn verifyPrehashed(self: Self, alloc: Allocator, msg_hash: [Hash.digest_length]u8, public_key: PublicKey) !void {
                var st = try self.verifier(alloc, public_key);
                return st.verifyPrehashed(msg_hash);
            }

            /// Return the raw signature bytes.
            pub fn toBytes(self: Self) []u8 {
                return self.bytes;
            }

            /// Create a signature from a bytes.
            pub fn fromBytes(bytes: []u8) Self {
                return .{
                    .bytes = bytes,
                };
            }
        };

        pub const Signer = struct {
            alloc: Allocator,
            h: Hash,
            secret_key: SecretKey,

            const Self = @This();

            pub fn init(alloc: Allocator, secret_key: SecretKey) Self {
                return .{
                    .alloc = alloc,
                    .h = Hash.init(.{}),
                    .secret_key = secret_key,
                };
            }

            pub fn update(self: *Self, data: []const u8) void {
                self.h.update(data);
            }

            fn finalizePrehashed(self: *Self, msg_hash: [Hash.digest_length]u8) !X931T.Signature {
                const pk = self.secret_key.public_key;
                const k = pk.size();

                const hash_id = comptime X931T.hashID(Hash);

                const em = try X931T.emsaX931Encode(self.alloc, &msg_hash, k, hash_id);
                defer self.alloc.free(em);

                const sig = try Crypt.decryptWithCheck(self.alloc, self.secret_key, em);

                const siged = X931T.Signature.fromBytes(sig);
                return siged;
            }

            pub fn finalize(self: *Self) !X931T.Signature {
                var hashed: [Hash.digest_length]u8 = undefined;
                self.h.final(&hashed);
                const sig = self.finalizePrehashed(hashed);
                return sig;
            }
        };

        pub const Verifier = struct {
            alloc: Allocator,
            h: Hash,
            sig: []u8,
            public_key: PublicKey,

            const Self = @This();

            fn init(alloc: Allocator, sig: X931T.Signature, public_key: PublicKey) Self {
                return .{
                    .alloc = alloc,
                    .h = Hash.init(.{}),
                    .sig = sig.bytes,
                    .public_key = public_key,
                };
            }

            pub fn update(self: *Self, data: []const u8) void {
                self.h.update(data);
            }

            fn verifyPrehashed(self: *Self, msg_hash: [Hash.digest_length]u8) !void {
                const pk = self.public_key;
                const k = pk.size();

                const em = try Crypt.encrypt(self.alloc, pk, self.sig);
                defer self.alloc.free(em);

                const hash_id = comptime X931T.hashID(Hash);

                const expected = try X931T.emsaX931Encode(self.alloc, &msg_hash, k, hash_id);
                defer self.alloc.free(expected);

                if (!std.mem.eql(u8, expected, em)) {
                    return error.RsaVerifyFail;
                }
            }

            pub fn verify(self: *Self) !void {
                var hashed: [Hash.digest_length]u8 = undefined;
                self.h.final(&hashed);
                try self.verifyPrehashed(hashed);
            }
        };

        /// sign with no hash msg
        pub fn signPlain(alloc: Allocator, secret_key: SecretKey, msg: []const u8) ![]u8 {
            const pk = secret_key.public_key;

            const k = pk.size();

            const em = try X931T.emsaX931Encode(alloc, msg, k, &[_]u8{});
            defer alloc.free(em);

            const sig = try Crypt.decryptWithCheck(alloc, secret_key, em);
            return sig;
        }

        pub fn verifyPlain(alloc: Allocator, public_key: PublicKey, msg: []const u8, sig: []u8) !void {
            const em = try Crypt.encrypt(alloc, public_key, sig);
            defer alloc.free(em);

            const k = public_key.size();

            const expected = try X931T.emsaX931Encode(alloc, msg, k, &[_]u8{});
            defer alloc.free(expected);

            if (!std.mem.eql(u8, expected, em)) {
                return error.RsaVerifyFail;
            }
        }

        /// X931 Encrypted Message Signature Appendix
        fn emsaX931Encode(alloc: Allocator, m_hash: []const u8, em_len: usize, hash_id: []const u8) ![]u8 {
            const h_len = m_hash.len;
            const j = em_len - h_len - hash_id.len - 2;
            if (j < 0) {
                return error.RsaMessageTooLong;
            }

            var em = try alloc.alloc(u8, em_len);
            em[0] = 0x6b;
            @memset(em[1..j], 0xbb);
            em[j] = 0xba;
            @memcpy(em[em_len - h_len - hash_id.len - 1 ..][0..h_len], m_hash);
            @memcpy(em[em_len - hash_id.len - 1 ..][0..hash_id.len], hash_id);
            em[em_len - 1] = 0xcc;

            return em;
        }

        fn hashID(HashType: type) []const u8 {
            return &switch (HashType) {
                std.crypto.hash.Sha1 => .{0x33},
                sha2.Sha256 => .{0x34},
                sha2.Sha384 => .{0x36},
                sha2.Sha512 => .{0x35},
                else => @compileError("unknown Hash " ++ @typeName(Hash)),
            };
        }
    };
}

// generateKey generates an RSA keypair of the given bit size using the
// random source random.
pub fn generateKey(alloc: Allocator, random: Random, bits: usize) !KeyPair {
    return KeyPair.generate(alloc, random, bits);
}

pub fn generateMultiPrimeKey(alloc: Allocator, random: Random, bits: usize, nprimes: usize) !KeyPair {
    return KeyPair.generateMultiPrimeKey(alloc, random, bits, nprimes);
}

pub fn generateX931Key(alloc: Allocator, random: Random, bits: usize) !KeyPair {
    return KeyPair.generateX931(alloc, random, bits);
}

/// Encrypt a short message using RSAES-PKCS1-v1_5.
pub fn encryptPkcs1v15(
    alloc: Allocator,
    random: Random,
    public_key: PublicKey,
    msg: []const u8,
) ![]const u8 {
    return Crypt.Pkcs1v15.encrypt(alloc, random, public_key, msg);
}

pub fn decryptPkcs1v15(
    alloc: Allocator,
    secret_key: SecretKey,
    ciphertext: []const u8,
) ![]const u8 {
    return Crypt.Pkcs1v15.decrypt(alloc, secret_key, ciphertext);
}

pub fn encryptSecretKeyPkcs1v15(
    alloc: Allocator,
    secret_key: SecretKey,
    msg: []const u8,
) ![]const u8 {
    return Crypt.Pkcs1v15.encryptSecretKey(alloc, secret_key, msg);
}

pub fn decryptPublicKeyPkcs1v15(
    alloc: Allocator,
    public_key: PublicKey,
    ciphertext: []const u8,
) ![]const u8 {
    return Crypt.Pkcs1v15.decryptPublicKey(alloc, public_key, ciphertext);
}

/// Encrypt a short message using Optimal Asymmetric Encryption Padding (RSAES-OAEP).
pub fn encryptOaep(
    alloc: Allocator,
    random: Random,
    public_key: PublicKey,
    comptime Hash: type,
    msg: []const u8,
    label: []const u8,
) ![]const u8 {
    return Crypt.Oaep.encrypt(alloc, random, public_key, Hash, msg, label);
}

pub fn decryptOaep(
    alloc: Allocator,
    secret_key: SecretKey,
    comptime Hash: type,
    ciphertext: []const u8,
    label: []const u8,
) ![]const u8 {
    return Crypt.Oaep.decrypt(alloc, secret_key, Hash, ciphertext, label);
}

/// Encrypt a short message using Optimal Asymmetric Encryption Padding (RSAES-OAEP).
pub fn encryptOaepWithOptions(
    alloc: Allocator,
    random: Random,
    public_key: PublicKey,
    msg: []const u8,
    opts: Crypt.Oaep.Options,
) ![]const u8 {
    return Crypt.Oaep.encryptWithOptions(alloc, random, public_key, msg, opts);
}

pub fn decryptOaepWithOptions(
    alloc: Allocator,
    secret_key: SecretKey,
    ciphertext: []const u8,
    opts: Crypt.Oaep.Options,
) ![]const u8 {
    return Crypt.Oaep.decryptWithOptions(alloc, secret_key, ciphertext, opts);
}

pub fn signPkcs1v15(
    alloc: Allocator,
    secret_key: SecretKey,
    comptime Hash: type,
    msg: []const u8,
) ![]u8 {
    var st = PKCS1v15(Hash).Signer.init(alloc, secret_key);
    st.update(msg);
    const sig = try st.finalize();

    const siged = sig.toBytes();
    return siged;
}

pub fn verifyPkcs1v15(
    alloc: Allocator,
    public_key: PublicKey,
    comptime Hash: type,
    msg: []const u8,
    sig: []u8,
) !void {
    var sign = PKCS1v15(Hash).Signature.fromBytes(sig);
    try sign.verify(alloc, msg, public_key);
}

pub fn signPss(
    alloc: Allocator,
    random: Random,
    secret_key: SecretKey,
    comptime Hash: type,
    msg: []const u8,
    opts: PSSOptions,
) ![]u8 {
    var st = Pss(Hash).Signer.init(alloc, random, secret_key, opts);
    st.update(msg);
    const sig = try st.finalize();

    const siged = sig.toBytes();
    return siged;
}

pub fn verifyPss(
    alloc: Allocator,
    public_key: PublicKey,
    comptime Hash: type,
    msg: []const u8,
    sig: []u8,
    opts: PSSOptions,
) !void {
    var sign = Pss(Hash).Signature.fromBytes(sig);
    try sign.verify(alloc, msg, public_key, opts);
}

pub fn signX931(
    alloc: Allocator,
    secret_key: SecretKey,
    comptime Hash: type,
    msg: []const u8,
) ![]u8 {
    var st = X931(Hash).Signer.init(alloc, secret_key);
    st.update(msg);
    const sig = try st.finalize();

    const siged = sig.toBytes();
    return siged;
}

pub fn verifyX931(
    alloc: Allocator,
    public_key: PublicKey,
    comptime Hash: type,
    msg: []const u8,
    sig: []u8,
) !void {
    var sign = X931(Hash).Signature.fromBytes(sig);
    try sign.verify(alloc, msg, public_key);
}

// incCounter increments a four byte, big-endian counter.
fn incCounter(c: *[4]u8) void {
    c[3] +%= 1;
    if (c[3] != 0) {
        return;
    }

    c[2] +%= 1;
    if (c[2] != 0) {
        return;
    }

    c[1] +%= 1;
    if (c[1] != 0) {
        return;
    }

    c[0] +%= 1;
}

/// mgf1XOR XORs the bytes in out with a mask generated using the MGF1 function
/// specified in PKCS #1 v2.1.
fn mgf1XOR(comptime HashType: type, seed: []const u8, out: []u8) void {
    var counter: [4]u8 = [_]u8{0} ** 4;
    var digest: [HashType.digest_length]u8 = undefined;

    var i: usize = 0;
    var done: usize = 0;
    while (done < out.len) {
        var hasher = HashType.init(.{});
        hasher.update(seed);
        hasher.update(&counter);
        hasher.final(&digest);

        i = 0;
        while (i < digest.len and done < out.len) : (i += 1) {
            out[done] ^= digest[i];
            done += 1;
        }

        incCounter(&counter);
    }
}

const ct = if (std.options.side_channels_mitigations == .none) ct_unprotected else ct_protected;

const ct_unprotected = struct {
    fn lastIndexOfScalar(slice: []const u8, value: u8) ?usize {
        return std.mem.lastIndexOfScalar(u8, slice, value);
    }

    fn indexOfScalarPos(slice: []const u8, start_index: usize, value: u8) ?usize {
        return std.mem.indexOfScalarPos(u8, slice, start_index, value);
    }

    fn memEql(a: []const u8, b: []const u8) bool {
        return std.mem.eql(u8, a, b);
    }

    fn @"and"(a: bool, b: bool) bool {
        return a and b;
    }

    fn @"or"(a: bool, b: bool) bool {
        return a or b;
    }
};

const ct_protected = struct {
    fn lastIndexOfScalar(slice: []const u8, value: u8) ?usize {
        var res: ?usize = null;
        var i: usize = slice.len;
        while (i != 0) {
            i -= 1;
            if (@intFromBool(res == null) & @intFromBool(slice[i] == value) == 1) res = i;
        }
        return res;
    }

    fn indexOfScalarPos(slice: []const u8, start_index: usize, value: u8) ?usize {
        var res: ?usize = null;
        for (slice[start_index..], start_index..) |c, j| {
            if (c == value) res = j;
        }
        return res;
    }

    fn memEql(a: []const u8, b: []const u8) bool {
        var res: u1 = 1;
        for (a, b) |a_elem, b_elem| {
            res &= @intFromBool(a_elem == b_elem);
        }
        return res == 1;
    }

    fn @"and"(a: bool, b: bool) bool {
        return (@intFromBool(a) & @intFromBool(b)) == 1;
    }

    fn @"or"(a: bool, b: bool) bool {
        return (@intFromBool(a) | @intFromBool(b)) == 1;
    }
};

test "mgf1XOR" {
    const Hash = std.crypto.hash.sha2.Sha256;
    var out = [_]u8{0} ** (Hash.digest_length * 2 + 1);

    mgf1XOR(Hash, "asdf", out[0 .. Hash.digest_length - 1]);
    try std.testing.expectEqualSlices(
        u8,
        &utils.hexToBytes(
            \\ed 1b 84 6b b9 26 39 00  c8 17 82 ad 08 eb 17 01
            \\fa 8c 72 21 c6 57 63 77  31 7f 5c e8 09 89 9f
        ),
        out[0 .. Hash.digest_length - 1],
    );

    var out2 = [_]u8{0} ** (Hash.digest_length * 2 + 1);

    mgf1XOR(Hash, "asdf", &out2);
    try std.testing.expectEqualSlices(
        u8,
        &utils.hexToBytes(
            \\ed 1b 84 6b b9 26 39 00  c8 17 82 ad 08 eb 17 01
            \\fa 8c 72 21 c6 57 63 77  31 7f 5c e8 09 89 9f 5a
            \\22 F2 80 D5 28 08 F4 93  83 76 00 DE 09 E4 EC 92
            \\4A 2C 7C EF 0D F7 7B BE  8F 7F 12 CB 8F 33 A6 65
            \\AB
        ),
        out2[0..],
    );
}

test "ct" {
    const c = ct_unprotected;
    try std.testing.expectEqual(true, c.@"or"(true, false));
    try std.testing.expectEqual(true, c.@"and"(true, true));
    try std.testing.expectEqual(true, c.memEql("Asdf", "Asdf"));
    try std.testing.expectEqual(false, c.memEql("asdf", "Asdf"));
    try std.testing.expectEqual(3, c.indexOfScalarPos("asdff", 1, 'f'));
    try std.testing.expectEqual(4, c.lastIndexOfScalar("asdff", 'f'));
}

test {
    _ = @import("subtle.zig");
    _ = @import("rsa_test.zig");
}
