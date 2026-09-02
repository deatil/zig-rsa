const std = @import("std");
const fmt = std.fmt;
const ff = std.crypto.ff;
const testing = std.testing;
const asn1 = std.crypto.codecs.asn1;
const Random = std.Random;
const Allocator = std.mem.Allocator;

pub const der = @import("der.zig");
pub const oids = @import("oid.zig");
pub const utils = @import("utils.zig");

pub const max_modulus_bits = 4096;
pub const max_modulus_len = max_modulus_bits / 8;

const FeUint = ff.Uint(max_modulus_bits);
const Modulus = ff.Modulus(max_modulus_bits);
const Fe = Modulus.Fe;

pub const pss_salt_length_auto = 0;

const oid_rsa_publickey = "1.2.840.113549.1.1.1";

const PrikeyData = struct {
    version: i32,
    n: i128,
    e: i32,
    d: i128,
    p: i128,
    q: i128,
};

const PubkeyData = struct {
    n: i128,
    e: i32,
};

pub const OAEPOptions = struct {
    hash: type,
    mgf_hash: ?type = null,
    label: []const u8 = "",
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

    pub fn fromBytes(mod: []const u8, exp: []const u8) !PublicKey {
        const n = try Modulus.fromBytes(mod, .big);
        if (n.bits() <= 512) {
            return error.InsecureBitCount;
        }

        const e = try Fe.fromBytes(n, exp, .big);

        if (std.debug.runtime_safety) {
            // > the RSA public exponent e is an integer between 3 and n - 1 satisfying
            // > GCD(e,\lambda(n)) = 1, where \lambda(n) = LCM(r_1 - 1, ..., r_u - 1)
            const e_v = e.toPrimitive(u32) catch return error.Exponent;
            if (!e.isOdd()) return error.Exponent;
            if (e_v < 3) return error.Exponent;
            if (n.v.compare(e.v) == .lt) return error.Exponent;
        }

        return .{
            .n = n,
            .e = e,
        };
    }

    pub fn fromDer(bytes: []const u8) !PublicKey {
        var parser = der.Parser{ .bytes = bytes };

        const seq = try parser.expectSequence();
        defer parser.seek(seq.slice.end);

        const modulus = try parser.expectPrimitive(.integer);
        const pub_exp = try parser.expectPrimitive(.integer);

        const n = parser.view(modulus);
        const e = parser.view(pub_exp);

        return Self.fromBytes(n, e);
    }

    pub fn fromPKCS8Der(bytes: []const u8) !PublicKey {
        var parser = der.Parser{ .bytes = bytes };
        const seq = try parser.expectSequence();

        const oid_seq = try parser.expectSequence();
        const oid = try parser.expectOid();

        try checkRSAPublickeyOid(oid);

        parser.seek(oid_seq.slice.end);
        const pubkey = try parser.expectBitstring();

        _ = seq;

        return Self.fromDer(pubkey.bytes);
    }

    pub fn fromDerAuto(bytes: []const u8) !PublicKey {
        const pk = Self.fromPKCS8Der(bytes) catch {
            return Self.fromDer(bytes);
        };

        return pk;
    }

    pub fn makeDer(self: Self, alloc: Allocator) ![]const u8 {
        const n = try self.n.v.toPrimitive(i128);
        const e = try self.e.toPrimitive(i32);

        const value = PubkeyData{
            .n = n,
            .e = e,
        };

        const ders = try asn1.der.encode(alloc, value);
        return ders;
    }

    /// Encrypt a short message using RSAES-PKCS1-v1_5.
    pub fn encryptPkcs1v15(self: Self, random: std.Random, msg: []const u8, out: []u8) ![]const u8 {
        // align variable names with spec
        const k = utils.byteLen(self.n.bits());
        if (out.len < k) return error.BufferTooSmall;
        if (msg.len > k - 11) return error.MessageTooLong;

        // EM = 0x00 || 0x02 || PS || 0x00 || M.
        var em = out[0..k];
        em[0] = 0;
        em[1] = 2;

        const ps = em[2..][0 .. k - msg.len - 3];

        // Section: 7.2.1
        // PS consists of pseudo-randomly generated nonzero octets.
        for (ps) |*v| {
            v.* = random.uintLessThan(u8, 0xff) + 1;
        }

        em[em.len - msg.len - 1] = 0;
        @memcpy(em[em.len - msg.len ..][0..msg.len], msg);

        const m = try Fe.fromBytes(self.n, em, .big);
        const e = try self.n.powPublic(m, self.e);
        try e.toBytes(em, .big);
        return em;
    }

    /// Encrypt a short message using Optimal Asymmetric Encryption Padding (RSAES-OAEP).
    pub fn encryptOaep(
        self: Self,
        random: std.Random,
        comptime Hash: type,
        msg: []const u8,
        label: []const u8,
        out: []u8,
    ) ![]const u8 {
        return self.encryptOaepInternal(random, Hash, Hash, msg, label, out);
    }

    pub fn encryptOaepWithOptions(
        self: Self,
        random: std.Random,
        msg: []const u8,
        out: []u8,
        opts: OAEPOptions,
    ) ![]const u8 {
        if (opts.mgf_hash) |mgf_hash| {
            return self.encryptOaepInternal(random, opts.hash, mgf_hash, msg, opts.label, out);
        }

        return self.encryptOaepInternal(random, opts.hash, opts.hash, msg, opts.label, out);
    }

    /// Encrypt a short message using Optimal Asymmetric Encryption Padding (RSAES-OAEP).
    fn encryptOaepInternal(
        self: Self,
        random: std.Random,
        comptime Hash: type,
        comptime MgfHash: type,
        msg: []const u8,
        label: []const u8,
        out: []u8,
    ) ![]const u8 {
        // align variable names with spec
        const k = utils.byteLen(self.n.bits());
        if (out.len < k) return error.BufferTooSmall;

        if (msg.len > k - 2 * Hash.digest_length - 2) return error.MessageTooLong;

        // EM = 0x00 || maskedSeed || maskedDB.
        var em = out[0..k];
        em[0] = 0;
        const seed = em[1..][0..Hash.digest_length];

        random.bytes(seed);

        // DB = lHash || PS || 0x01 || M.
        var db = em[1 + seed.len ..];
        const lHash = labelHash(Hash, label);
        @memcpy(db[0..lHash.len], &lHash);
        @memset(db[lHash.len .. db.len - msg.len - 2], 0);
        db[db.len - msg.len - 1] = 1;
        @memcpy(db[db.len - msg.len ..], msg);

        var mgf_buf: [max_modulus_len]u8 = undefined;

        const db_mask = mgf1(MgfHash, seed, mgf_buf[0..db.len]);
        for (db, db_mask) |*v, m| v.* ^= m;

        const seed_mask = mgf1(MgfHash, db, mgf_buf[0..seed.len]);
        for (seed, seed_mask) |*v, m| v.* ^= m;

        const m = try Fe.fromBytes(self.n, em, .big);
        const e = try self.n.powPublic(m, self.e);
        try e.toBytes(em, .big);
        return em;
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

pub const SecretKey = struct {
    public_key: PublicKey,
    d: Fe,
    primes: []Fe,

    // Precomputed contains precomputed values that speed up private
    // operations, if available.
    precomputed: ?PrecomputedValues = null,

    const Self = @This();

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
        nbytes: []const u8,
        ebytes: []const u8,
        dbytes: []const u8,
        pbytes: []const u8,
        qbytes: []const u8,
    ) !SecretKey {
        const pubkey = try PublicKey.fromBytes(nbytes, ebytes);

        const d = try Fe.fromBytes(pubkey.n, dbytes, .big);
        const p = try Fe.fromBytes(pubkey.n, pbytes, .big);
        const q = try Fe.fromBytes(pubkey.n, qbytes, .big);

        // check that n = p * q
        const expected_zero = pubkey.n.mul(p, q);
        if (!expected_zero.isZero()) return error.KeyMismatch;

        // > The RSA private exponent d is a positive integer less than n
        // > satisfying e * d == 1 (mod \lambda(n)),
        if (!d.isOdd()) return error.Exponent;
        if (d.v.compare(pubkey.n.v) != .lt) return error.Exponent;

        var primes = [_]Fe{ p, q };

        return .{
            .public_key = pubkey,
            .d = d,
            .primes = &primes,
        };
    }

    pub fn fromDer(bytes: []const u8) !SecretKey {
        var parser = der.Parser{ .bytes = bytes };
        const seq = try parser.expectSequence();
        const version = try parser.expectInt(u8);

        const mod = try parser.expectPrimitive(.integer);
        const pub_exp = try parser.expectPrimitive(.integer);

        const sec_exp = try parser.expectPrimitive(.integer);
        const prime1 = try parser.expectPrimitive(.integer);
        const prime2 = try parser.expectPrimitive(.integer);

        _ = seq;

        switch (version) {
            0 => {},
            1 => {},
            else => return error.InvalidVersion,
        }

        const n = parser.view(mod);
        const e = parser.view(pub_exp);

        const d = parser.view(sec_exp);
        const p = parser.view(prime1);
        const q = parser.view(prime2);

        return Self.fromBytes(n, e, d, p, q);
    }

    pub fn fromPKCS8Der(bytes: []const u8) !SecretKey {
        var parser = der.Parser{ .bytes = bytes };
        _ = try parser.expectSequence();

        const version = try parser.expectInt(u8);
        if (version != 0) {
            return error.PKCS8VersionError;
        }

        const oid_seq = try parser.expectSequence();
        const oid = try parser.expectOid();

        try checkRSAPublickeyOid(oid);

        parser.seek(oid_seq.slice.end);
        const prikey = try parser.expect(.universal, false, .octetstring);

        const prikey_bytes = parser.view(prikey);
        return Self.fromDer(prikey_bytes);
    }

    pub fn fromDerAuto(bytes: []const u8) !SecretKey {
        const sk = Self.fromPKCS8Der(bytes) catch {
            return Self.fromDer(bytes);
        };

        return sk;
    }

    pub fn decryptPkcs1v15(self: Self, ciphertext: []const u8, out: []u8) ![]const u8 {
        const k = utils.byteLen(self.public_key.n.bits());
        if (out.len < k) return error.BufferTooSmall;

        const em = out[0..k];

        const m = try Fe.fromBytes(self.public_key.n, ciphertext, .big);
        const e = try self.public_key.n.pow(m, self.d);
        try e.toBytes(em, .big);

        // Care shall be taken to ensure that an opponent cannot
        // distinguish these error conditions, whether by error
        // message or timing.
        const msg_start = ct.lastIndexOfScalar(em, 0) orelse em.len;
        const ps_len = em.len - msg_start;
        if (ct.@"or"(em[0] != 0, ct.@"or"(em[1] != 2, ps_len < 8))) {
            return error.Inconsistent;
        }

        return em[msg_start + 1 ..];
    }

    pub fn decryptOaep(
        self: Self,
        comptime Hash: type,
        ciphertext: []const u8,
        label: []const u8,
        out: []u8,
    ) ![]u8 {
        return self.decryptOaepInternal(Hash, Hash, ciphertext, label, out);
    }

    pub fn decryptOaepWithOptions(
        self: Self,
        ciphertext: []const u8,
        out: []u8,
        opts: OAEPOptions,
    ) ![]u8 {
        if (opts.mgf_hash) |mgf_hash| {
            return self.decryptOaepInternal(opts.hash, mgf_hash, ciphertext, opts.label, out);
        }

        return self.decryptOaepInternal(opts.hash, opts.hash, ciphertext, opts.label, out);
    }

    fn decryptOaepInternal(
        self: Self,
        comptime Hash: type,
        comptime MgfHash: type,
        ciphertext: []const u8,
        label: []const u8,
        out: []u8,
    ) ![]u8 {
        // align variable names with spec
        const k = utils.byteLen(self.public_key.n.bits());
        if (out.len < k) return error.BufferTooSmall;

        const mod = try Fe.fromBytes(self.public_key.n, ciphertext, .big);
        const exp = self.public_key.n.pow(mod, self.d) catch unreachable;
        const em = out[0..k];
        try exp.toBytes(em, .big);

        const y = em[0];
        const seed = em[1..][0..Hash.digest_length];
        const db = em[1 + Hash.digest_length ..];

        var mgf_buf: [max_modulus_len]u8 = undefined;

        const seed_mask = mgf1(MgfHash, db, mgf_buf[0..seed.len]);
        for (seed, seed_mask) |*v, m| v.* ^= m;

        const db_mask = mgf1(MgfHash, seed, mgf_buf[0..db.len]);
        for (db, db_mask) |*v, m| v.* ^= m;

        const expected_hash = labelHash(Hash, label);
        const actual_hash = db[0..expected_hash.len];

        // Care shall be taken to ensure that an opponent cannot
        // distinguish these error conditions, whether by error
        // message or timing.
        const msg_start = ct.indexOfScalarPos(em, expected_hash.len + 1, 1) orelse 0;
        if (ct.@"or"(y != 0, ct.@"or"(msg_start == 0, !ct.memEql(&expected_hash, actual_hash)))) {
            return error.Inconsistent;
        }

        return em[msg_start + 1 ..];
    }

    /// decrypt short plaintext with secret key.
    pub fn decrypt(self: Self, plaintext: []const u8, out: []u8) !void {
        const n = self.public_key.n;
        const k = utils.byteLen(n.bits());
        if (plaintext.len > k) {
            return error.MessageTooLong;
        }

        const msg_as_int = try Fe.fromBytes(n, plaintext, .big);
        const enc_as_int = try n.pow(msg_as_int, self.d);
        try enc_as_int.toBytes(out, .big);
    }

    pub fn validate(self: Self) !void {
        if (self.public_key.n.v.isZero()) {
            return error.MissingPublicModulus;
        }

        const e_v = self.public_key.e.toPrimitive(u32) catch return error.Exponent;
        if (e_v < 2) {
            return error.PublicExponentTooSmall;
        }
    }

    // Precompute performs some calculations that speed up private key operations
    // in the future.
    pub fn precompute(self: *Self, alloc: Allocator) !void {
        if (self.precomputed != null) {
            return;
        }

        var pbuf: [max_modulus_len]u8 = undefined;
        try self.primes[0].toBytes(&pbuf, .big);
        const new_pbuf = utils.stripLeadingZeros(&pbuf);

        var qbuf: [max_modulus_len]u8 = undefined;
        try self.primes[1].toBytes(&qbuf, .big);
        const new_qbuf = utils.stripLeadingZeros(&qbuf);

        var ebuf: [max_modulus_len]u8 = undefined;
        try self.public_key.e.toBytes(&ebuf, .big);
        const new_ebuf = utils.stripLeadingZeros(&ebuf);

        const p = try Modulus.fromBytes(new_pbuf, .big);
        const q = try Modulus.fromBytes(new_qbuf, .big);

        var bp = try utils.bigFromBytes(alloc, new_pbuf);
        var bq = try utils.bigFromBytes(alloc, new_qbuf);
        var be = try utils.bigFromBytes(alloc, new_ebuf);

        defer bp.deinit();
        defer bq.deinit();
        defer be.deinit();

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
            return error.RsaPrecomputeFail;
        }

        defer bd.deinit();

        // dP = d mod (p-1), dQ = d mod (q-1).
        var quot = try utils.newBig(alloc);
        var bdp = try utils.newBig(alloc);
        try quot.divFloor(&bdp, &bd, &p1);
        var bdq = try utils.newBig(alloc);
        try quot.divFloor(&bdq, &bd, &q1);

        defer quot.deinit();
        defer bdp.deinit();
        defer bdq.deinit();

        const dp = try utils.feFromBig(p, &bdp);
        const dq = try utils.feFromBig(q, &bdq);

        // Zero CRT exponents are impossible for prime p, q (e·dP ≡ 1 mod p-1);
        // reject rather than trip `ff`'s NullExponent later on garbage input.
        if (dp.isZero() or dq.isZero()) {
            return error.RsaPrecomputeFail;
        }

        // qInv = q⁻¹ mod p = (q mod p)^(p-2) mod p — Fermat inversion, valid for
        // prime p, constant-time via `ff` (the exponent p-2 is secret).
        const q_mod_p = utils.reduceWide(p, q.v);
        if (q_mod_p.isZero()) {
            return error.RsaPrecomputeFail;
        }
        const two = try Fe.fromPrimitive(u8, p, 2);
        const p_minus_2 = p.sub(p.zero, two); // (0 - 2) mod p = p - 2
        const qinv = try p.pow(q_mod_p, p_minus_2);

        // Self-check qInv·q ≡ 1 (mod p): catches a non-prime p sneaking past.
        if (!p.mul(qinv, q_mod_p).eql(p.one())) {
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
};

pub const KeyPair = struct {
    public_key: PublicKey,
    secret_key: SecretKey,

    const Self = @This();

    pub fn generate(alloc: Allocator, random: std.Random, bits: usize) !Self {
        if (bits < utils.min_modulus_bits or bits > utils.max_modulus_bits or bits % 2 != 0) {
            return error.InvalidBits;
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

            if (pb.len > utils.max_modulus_len or qb.len > utils.max_modulus_len) {
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
                .primes = &primes,
            };
            try sk.precompute(alloc);

            return .{ .public_key = pk, .secret_key = sk };
        }
    }

    /// Return the public key corresponding to the secret key.
    pub fn fromSecretKey(secret_key: SecretKey) !KeyPair {
        return .{
            .secret_key = secret_key,
            .public_key = secret_key.public_key,
        };
    }

    pub fn signPkcs1v15(self: Self, comptime Hash: type, msg: []const u8, out: []u8) !PKCS1v15(Hash).Signature {
        var st = try self.signerPkcs1v15(Hash);
        st.update(msg);
        return st.finalize(out);
    }

    pub fn signerPkcs1v15(self: Self, comptime Hash: type) !PKCS1v15(Hash).Signer {
        return PKCS1v15(Hash).Signer.init(self.secret_key);
    }

    pub fn signPss(
        self: Self,
        random: std.Random,
        comptime Hash: type,
        msg: []const u8,
        salt: ?[]const u8,
        out: []u8,
    ) !Pss(Hash).Signature {
        var st = try self.signerPss(random, Hash, salt);
        st.update(msg);
        return st.finalize(out);
    }

    /// Salt must outlive returned `PSS.Signer`.
    pub fn signerPss(self: Self, random: std.Random, comptime Hash: type, salt: ?[]const u8) !Pss(Hash).Signer {
        return Pss(Hash).Signer.init(random, self.secret_key, salt);
    }
};

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

/// Signature Scheme with Appendix v1.5 (RSASSA-PKCS1-v1_5)
pub fn PKCS1v15(comptime Hash: type) type {
    return struct {
        const PkcsT = @This();

        pub const Signature = struct {
            bytes: []u8,

            const Self = @This();

            pub fn verifier(self: Self, public_key: PublicKey) !Verifier {
                return Verifier.init(self, public_key);
            }

            pub fn verify(self: Self, msg: []const u8, public_key: PublicKey) !void {
                var st = Verifier.init(self, public_key);
                st.update(msg);
                return st.verify();
            }

            /// Return the raw signature bytes.
            pub fn toBytes(self: Self) []u8 {
                return self.bytes;
            }

            /// Create a signature from a bytes.
            pub fn fromBytes(bytes: []u8) Self {
                return Signature{
                    .bytes = bytes,
                };
            }
        };

        pub const Signer = struct {
            h: Hash,
            secret_key: SecretKey,

            const Self = @This();

            pub fn init(secret_key: SecretKey) Signer {
                return .{
                    .h = Hash.init(.{}),
                    .secret_key = secret_key,
                };
            }

            pub fn update(self: *Self, data: []const u8) void {
                self.h.update(data);
            }

            pub fn finalize(self: *Self, out: []u8) !PkcsT.Signature {
                const k = utils.byteLen(self.secret_key.public_key.n.bits());

                var hash: [Hash.digest_length]u8 = undefined;
                self.h.final(&hash);

                const em = try PkcsT.emsaEncode(hash, out[0..k]);

                try self.secret_key.decrypt(em, em);

                return Signature.fromBytes(em);
            }
        };

        pub const Verifier = struct {
            h: Hash,
            sig: []u8,
            public_key: PublicKey,

            const Self = @This();

            fn init(sig: PkcsT.Signature, public_key: PublicKey) Verifier {
                return Verifier{
                    .h = Hash.init(.{}),
                    .sig = sig.bytes,
                    .public_key = public_key,
                };
            }

            pub fn update(self: *Self, data: []const u8) void {
                self.h.update(data);
            }

            pub fn verify(self: *Self) !void {
                const pk = self.public_key;
                const s = try Fe.fromBytes(pk.n, self.sig, .big);
                const emm = try pk.n.powPublic(s, pk.e);

                var em_buf: [max_modulus_len]u8 = undefined;
                const em = em_buf[0..utils.byteLen(pk.n.bits())];
                try emm.toBytes(em, .big);

                var hash: [Hash.digest_length]u8 = undefined;
                self.h.final(&hash);

                var em_buf2: [max_modulus_len]u8 = undefined;
                const em2 = em_buf2[0..utils.byteLen(pk.n.bits())];
                const expected = try PkcsT.emsaEncode(hash, em2);

                if (!std.mem.eql(u8, expected, em)) {
                    return error.Inconsistent;
                }
            }
        };

        /// PKCS Encrypted Message Signature Appendix
        fn emsaEncode(hash: [Hash.digest_length]u8, out: []u8) ![]u8 {
            const digest_header = comptime PkcsT.digestHeader();
            const tLen = digest_header.len + Hash.digest_length;
            const emLen = out.len;
            if (emLen < tLen + 11) return error.ModulusTooShort;
            if (out.len < emLen) return error.BufferTooSmall;

            var res = out[0..emLen];
            res[0] = 0;
            res[1] = 1;
            const padding_len = emLen - tLen - 3;
            @memset(res[2..][0..padding_len], 0xff);
            res[2 + padding_len] = 0;
            @memcpy(res[2 + padding_len + 1 ..][0..digest_header.len], digest_header);
            @memcpy(res[res.len - hash.len ..], &hash);

            return res;
        }

        /// DER encoded header. Sequence of digest algo + digest.
        fn digestHeader() []const u8 {
            const sha2 = std.crypto.hash.sha2;
            const sha3 = std.crypto.hash.sha3;

            // Section 9.2 Notes 1.
            return switch (Hash) {
                std.crypto.hash.Md5 => &utils.hexToBytes(
                    \\30 20 30 0c 06 08 2a 86 48 86 f7 0d 02 05 05 00 04 10
                ),
                std.crypto.hash.Sha1 => &utils.hexToBytes(
                    \\30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14
                ),
                sha2.Sha224 => &utils.hexToBytes(
                    \\30 2d 30 0d 06 09 60 86 48 01 65 03 04 02 04
                    \\05 00 04 1c
                ),
                sha2.Sha256 => &utils.hexToBytes(
                    \\30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00
                    \\04 20
                ),
                sha2.Sha384 => &utils.hexToBytes(
                    \\30 41 30 0d 06 09 60 86 48 01 65 03 04 02 02 05 00
                    \\04 30
                ),
                sha2.Sha512 => &utils.hexToBytes(
                    \\30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00
                    \\04 40
                ),
                sha2.Sha512_224 => &utils.hexToBytes(
                    \\30 2d 30 0d 06 09 60 86 48 01 65 03 04 02 05
                    \\05 00 04 1c
                ),
                sha2.Sha512_256 => &utils.hexToBytes(
                    \\30 31 30 0d 06 09 60 86 48 01 65 03 04 02 06
                    \\05 00 04 20
                ),
                sha3.Sha3_224 => &utils.hexToBytes(
                    \\30 2d 30 0d 06 09 60 86 48 01 65 03 04 02 07 
                    \\05 00 04 1C
                ),
                sha3.Sha3_256 => &utils.hexToBytes(
                    \\30 31 30 0d 06 09 60 86 48 01 65 03 04 02 08 
                    \\05 00 04 20
                ),
                sha3.Sha3_384 => &utils.hexToBytes(
                    \\30 41 30 0d 06 09 60 86 48 01 65 03 04 02 09 
                    \\05 00 04 30
                ),
                sha3.Sha3_512 => &utils.hexToBytes(
                    \\30 51 30 0d 06 09 60 86 48 01 65 03 04 02 0a 
                    \\05 00 04 40
                ),
                else => @compileError("unknown Hash " ++ @typeName(Hash)),
            };
        }
    };
}

/// Probabilistic Signature Scheme (RSASSA-PSS)
pub fn Pss(comptime Hash: type) type {
    // RFC 4055 S3.1
    const default_salt_len = Hash.digest_length;

    return struct {
        const PssT = @This();

        pub const Signature = struct {
            bytes: []u8,

            const Self = @This();

            pub fn verifier(self: Self, public_key: PublicKey) !Verifier {
                return Verifier.init(self, public_key);
            }

            pub fn verify(self: Self, msg: []const u8, public_key: PublicKey, salt_len: ?usize) !void {
                var st = Verifier.init(self, public_key, salt_len orelse default_salt_len);
                st.update(msg);
                return st.verify();
            }

            /// Return the raw signature bytes.
            pub fn toBytes(self: Self) []u8 {
                return self.bytes;
            }

            /// Create a signature from a bytes.
            pub fn fromBytes(bytes: []u8) Self {
                return Signature{
                    .bytes = bytes,
                };
            }
        };

        pub const Signer = struct {
            random: std.Random,
            h: Hash,
            secret_key: SecretKey,
            salt: ?[]const u8,

            const Self = @This();

            pub fn init(random: std.Random, secret_key: SecretKey, salt: ?[]const u8) Signer {
                return .{
                    .random = random,
                    .h = Hash.init(.{}),
                    .secret_key = secret_key,
                    .salt = salt,
                };
            }

            pub fn update(self: *Self, data: []const u8) void {
                self.h.update(data);
            }

            pub fn finalize(self: *Self, out: []u8) !PssT.Signature {
                var hashed: [Hash.digest_length]u8 = undefined;
                self.h.final(&hashed);

                const salt = if (self.salt) |s| s else brk: {
                    var res: [default_salt_len]u8 = undefined;

                    self.random.bytes(&res);
                    break :brk &res;
                };

                const em_bits = self.secret_key.public_key.n.bits() - 1;
                const em = try PssT.emsaPSSEncode(hashed, salt, em_bits, out);

                try self.secret_key.decrypt(em, em);

                return .{ .bytes = em };
            }
        };

        pub const Verifier = struct {
            h: Hash,
            sig: []u8,
            public_key: PublicKey,
            salt_len: usize,

            const Self = @This();

            fn init(sig: PssT.Signature, public_key: PublicKey, salt_len: usize) Verifier {
                return Verifier{
                    .h = Hash.init(.{}),
                    .sig = sig.bytes,
                    .public_key = public_key,
                    .salt_len = salt_len,
                };
            }

            pub fn update(self: *Self, data: []const u8) void {
                self.h.update(data);
            }

            pub fn verify(self: *Self) !void {
                const pk = self.public_key;

                var em_buf: [max_modulus_len]u8 = undefined;
                const em_bits = pk.n.bits() - 1;
                const em_len = std.math.divCeil(usize, em_bits, 8) catch unreachable;
                const em = em_buf[0..em_len];

                const s = try Fe.fromBytes(pk.n, self.sig, .big);
                const emm = try pk.n.powPublic(s, pk.e);
                try emm.toBytes(em, .big);

                var mHash: [Hash.digest_length]u8 = undefined;
                self.h.final(&mHash);

                const mod_bits = self.public_key.n.bits();
                try PssT.emsaPSSVerify(&mHash, em, mod_bits - 1, self.salt_len);
            }
        };

        /// PSS Encrypted Message Signature Appendix
        fn emsaPSSEncode(msg_hash: [Hash.digest_length]u8, salt: []const u8, em_bits: usize, out: []u8) ![]u8 {
            // emLen = \ceil(emBits/8)
            const em_len = ((em_bits - 1) / 8) + 1;
            const s_len = salt.len;

            if (em_len < Hash.digest_length + s_len + 2) return error.ErrMsgTooLong;

            // EM = maskedDB || H || 0xbc
            var em = out[0..em_len];
            em[em.len - 1] = 0xbc;

            // M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;
            // H = Hash(M')
            const hash = em[em.len - 1 - Hash.digest_length ..][0..Hash.digest_length];
            var hasher = Hash.init(.{});
            hasher.update(&([_]u8{0} ** 8));
            hasher.update(&msg_hash);
            hasher.update(salt);
            hasher.final(hash);

            // DB = PS || 0x01 || salt
            var db = em[0 .. em_len - Hash.digest_length - 1];
            @memset(db[0 .. db.len - s_len - 1], 0);
            db[db.len - s_len - 1] = 1;
            @memcpy(db[db.len - s_len ..], salt);

            var mgf_buf: [max_modulus_len]u8 = undefined;
            const mgf_len = em_len - Hash.digest_length - 1;
            const mgf_out = mgf_buf[0 .. ((mgf_len - 1) / Hash.digest_length + 1) * Hash.digest_length];
            var dbMask = mgf1(Hash, hash, mgf_out);
            dbMask = dbMask[0..mgf_len];

            var i: usize = 0;
            while (i < dbMask.len) : (i += 1) {
                db[i] = db[i] ^ dbMask[i];
            }

            // Set the leftmost 8emLen - emBits bits of the leftmost octet
            // in maskedDB to zero.
            const shift = std.math.comptimeMod(8 * em_len - em_bits, 8);
            const mask = @as(u8, 0xff) >> shift;
            db[0] &= mask;

            return em;
        }

        fn emsaPSSVerify(mHash: []const u8, em: []const u8, emBit: usize, slen: usize) !void {
            var sLen = slen;

            // 1.   If the length of M is greater than the input limitation for
            //      the hash function (2^61 - 1 octets for SHA-1), output
            //      "inconsistent" and stop.
            // All the cryptographic hash functions in the standard library have a limit of >= 2^61 - 1.
            // Even then, this check is only there for paranoia. In the context of TLS certificates, emBit cannot exceed 4096.
            if (emBit >= 1 << 61) {
                return error.InvalidSignature;
            }

            // emLen = \ceil(emBits/8)
            const emLen = ((emBit - 1) / 8) + 1;
            std.debug.assert(emLen == em.len);

            // 2.   Let mHash = Hash(M), an octet string of length hLen.
            const hlen = Hash.digest_length;
            if (hlen != mHash.len) {
                return error.InvalidSignature;
            }

            // 3.   If emLen < hLen + sLen + 2, output "inconsistent" and stop.
            if (emLen < Hash.digest_length + sLen + 2) {
                return error.InvalidSignature;
            }

            // 4.   If the rightmost octet of EM does not have hexadecimal value
            //      0xbc, output "inconsistent" and stop.
            if (em[em.len - 1] != 0xbc) {
                return error.InvalidSignature;
            }

            // 5.   Let maskedDB be the leftmost emLen - hLen - 1 octets of EM,
            //      and let H be the next hLen octets.
            const maskedDB = em[0..(emLen - Hash.digest_length - 1)];
            const h = em[(emLen - Hash.digest_length - 1)..(emLen - 1)][0..Hash.digest_length];

            // 6.   If the leftmost 8emLen - emBits bits of the leftmost octet in
            //      maskedDB are not all equal to zero, output "inconsistent" and
            //      stop.
            const zero_bits = emLen * 8 - emBit;
            var mask: u8 = maskedDB[0];
            var i: usize = 0;
            while (i < 8 - zero_bits) : (i += 1) {
                mask = mask >> 1;
            }
            if (mask != 0) {
                return error.InvalidSignature;
            }

            // 7.   Let dbMask = MGF(H, emLen - hLen - 1).
            const mgf_len = emLen - Hash.digest_length - 1;
            var mgf_out_buf: [512]u8 = undefined;
            if (mgf_len > mgf_out_buf.len) { // Modulus > 4096 bits
                return error.InvalidSignature;
            }

            const mgf_out = mgf_out_buf[0 .. ((mgf_len - 1) / Hash.digest_length + 1) * Hash.digest_length];
            var dbMask = mgf1(Hash, h, mgf_out);
            dbMask = dbMask[0..mgf_len];

            // 8.   Let DB = maskedDB \xor dbMask.
            i = 0;
            while (i < dbMask.len) : (i += 1) {
                dbMask[i] = maskedDB[i] ^ dbMask[i];
            }

            // 9.   Set the leftmost 8emLen - emBits bits of the leftmost octet
            //      in DB to zero.
            i = 0;
            mask = 0;
            while (i < 8 - zero_bits) : (i += 1) {
                mask = mask << 1;
                mask += 1;
            }
            dbMask[0] = dbMask[0] & mask;

            if (sLen == pss_salt_length_auto) {
                if (std.mem.indexOfScalar(u8, dbMask, 0x01)) |ps_len| {
                    sLen = dbMask.len - ps_len - 1;
                } else {
                    return error.ErrorVerification;
                }
            }

            // 10.  If the emLen - hLen - sLen - 2 leftmost octets of DB are not
            //      zero or if the octet at position emLen - hLen - sLen - 1 (the
            //      leftmost position is "position 1") does not have hexadecimal
            //      value 0x01, output "inconsistent" and stop.
            const ps_len = emLen - Hash.digest_length - sLen - 2;
            for (dbMask[0..ps_len]) |e| {
                if (e != 0x00) {
                    return error.InvalidSignature;
                }
            }

            if (dbMask[ps_len] != 0x01) {
                return error.InvalidSignature;
            }

            // 11.  Let salt be the last sLen octets of DB.
            const salt = dbMask[(dbMask.len - sLen)..];

            // 12.  Let
            //         M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt ;
            //      M' is an octet string of length 8 + hLen + sLen with eight
            //      initial zero octets.
            // 13.  Let H' = Hash(M'), an octet string of length hLen.
            var h_p: [Hash.digest_length]u8 = undefined;
            var hasher = Hash.init(.{});
            hasher.update(&([_]u8{0} ** 8));
            hasher.update(mHash);
            hasher.update(salt);
            hasher.final(&h_p);

            // 14.  If H = H', output "consistent".  Otherwise, output
            //      "inconsistent".
            if (!std.mem.eql(u8, h, &h_p)) {
                return error.InvalidSignature;
            }
        }
    };
}

pub fn generate(alloc: Allocator, random: std.Random, bits: usize) !KeyPair {
    return KeyPair.generate(alloc, random, bits);
}

/// Encrypt a short message using RSAES-PKCS1-v1_5.
pub fn encryptPkcs1v15(
    alloc: Allocator,
    random: std.Random,
    public_key: PublicKey,
    msg: []const u8,
) ![]const u8 {
    var out: [max_modulus_len]u8 = undefined;
    const encrypted = try public_key.encryptPkcs1v15(random, msg, &out);
    return alloc.dupe(u8, encrypted[0..]);
}

pub fn decryptPkcs1v15(alloc: Allocator, secret_key: SecretKey, ciphertext: []const u8) ![]const u8 {
    var out: [max_modulus_len]u8 = undefined;
    const decrypted = try secret_key.decryptPkcs1v15(ciphertext, &out);
    return alloc.dupe(u8, decrypted[0..]);
}

/// Encrypt a short message using Optimal Asymmetric Encryption Padding (RSAES-OAEP).
pub fn encryptOaep(
    alloc: Allocator,
    random: std.Random,
    public_key: PublicKey,
    comptime Hash: type,
    msg: []const u8,
    label: []const u8,
) ![]const u8 {
    var out: [max_modulus_len]u8 = undefined;
    const encrypted = try public_key.encryptOaep(random, Hash, msg, label, &out);
    return alloc.dupe(u8, encrypted[0..]);
}

pub fn decryptOaep(
    alloc: Allocator,
    secret_key: SecretKey,
    comptime Hash: type,
    ciphertext: []const u8,
    label: []const u8,
) ![]const u8 {
    var out: [max_modulus_len]u8 = undefined;
    const decrypted = try secret_key.decryptOaep(Hash, ciphertext, label, &out);
    return alloc.dupe(u8, decrypted[0..]);
}

/// Encrypt a short message using Optimal Asymmetric Encryption Padding (RSAES-OAEP).
pub fn encryptOaepWithOptions(
    alloc: Allocator,
    random: std.Random,
    public_key: PublicKey,
    msg: []const u8,
    opts: OAEPOptions,
) ![]const u8 {
    var out: [max_modulus_len]u8 = undefined;
    const encrypted = try public_key.encryptOaepWithOptions(random, msg, &out, opts);
    return alloc.dupe(u8, encrypted[0..]);
}

pub fn decryptOaepWithOptions(
    alloc: Allocator,
    secret_key: SecretKey,
    ciphertext: []const u8,
    opts: OAEPOptions,
) ![]const u8 {
    var out: [max_modulus_len]u8 = undefined;
    const decrypted = try secret_key.decryptOaepWithOptions(ciphertext, &out, opts);
    return alloc.dupe(u8, decrypted[0..]);
}

pub fn signPkcs1v15(
    alloc: Allocator,
    secret_key: SecretKey,
    comptime Hash: type,
    msg: []const u8,
) ![]u8 {
    var st = PKCS1v15(Hash).Signer.init(secret_key);
    st.update(msg);

    var out: [max_modulus_len]u8 = undefined;
    const sig = try st.finalize(&out);

    const siged = sig.toBytes();
    return alloc.dupe(u8, siged[0..]);
}

pub fn verifyPkcs1v15(
    public_key: PublicKey,
    comptime Hash: type,
    msg: []const u8,
    sig: []u8,
) !void {
    var sign = PKCS1v15(Hash).Signature.fromBytes(sig);
    try sign.verify(
        msg,
        public_key,
    );
}

pub fn signPss(
    alloc: Allocator,
    random: std.Random,
    secret_key: SecretKey,
    comptime Hash: type,
    msg: []const u8,
    salt: ?[]const u8,
) ![]u8 {
    var st = Pss(Hash).Signer.init(random, secret_key, salt);
    st.update(msg);

    var out: [max_modulus_len]u8 = undefined;
    const sig = try st.finalize(&out);

    const siged = sig.toBytes();
    return alloc.dupe(u8, siged[0..]);
}

pub fn verifyPss(
    public_key: PublicKey,
    comptime Hash: type,
    msg: []const u8,
    sig: []u8,
    salt_len: ?usize,
) !void {
    var sign = Pss(Hash).Signature.fromBytes(sig);
    try sign.verify(
        msg,
        public_key,
        salt_len,
    );
}

/// Mask generation function. Currently the only one defined.
fn mgf1(comptime Hash: type, seed: []const u8, out: []u8) []u8 {
    var c: [@sizeOf(u32)]u8 = undefined;
    var tmp: [Hash.digest_length]u8 = undefined;

    var i: usize = 0;
    var counter: u32 = 0;
    while (i < out.len) : (counter += 1) {
        var hasher = Hash.init(.{});
        hasher.update(seed);
        std.mem.writeInt(u32, &c, counter, .big);
        hasher.update(&c);

        const left = out.len - i;
        if (left >= Hash.digest_length) {
            // optimization: write straight to `out`
            hasher.final(out[i..][0..Hash.digest_length]);
            i += Hash.digest_length;
        } else {
            hasher.final(&tmp);
            @memcpy(out[i..][0..left], tmp[0..left]);
            i += left;
        }
    }

    return out;
}

/// For OAEP.
inline fn labelHash(comptime Hash: type, label: []const u8) [Hash.digest_length]u8 {
    if (label.len == 0) {
        // magic constants from NIST
        const sha2 = std.crypto.hash.sha2;

        switch (Hash) {
            std.crypto.hash.Sha1 => return utils.hexToBytes(
                \\da39a3ee 5e6b4b0d 3255bfef 95601890
                \\afd80709
            ),
            sha2.Sha256 => return utils.hexToBytes(
                \\e3b0c442 98fc1c14 9afbf4c8 996fb924
                \\27ae41e4 649b934c a495991b 7852b855
            ),
            sha2.Sha384 => return utils.hexToBytes(
                \\38b060a7 51ac9638 4cd9327e b1b1e36a
                \\21fdb711 14be0743 4c0cc7bf 63f6e1da
                \\274edebf e76f65fb d51ad2f1 4898b95b
            ),
            sha2.Sha512 => return utils.hexToBytes(
                \\cf83e135 7eefb8bd f1542850 d66d8007
                \\d620e405 0b5715dc 83f4a921 d36ce9ce
                \\47d0d13c 5d85f2b0 ff8318d2 877eec2f
                \\63b931bd 47417a81 a538327a f927da3e
            ),
            // just use the empty hash...
            else => {},
        }
    }

    var res: [Hash.digest_length]u8 = undefined;
    Hash.hash(label, &res, .{});
    return res;
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

test "mgf1" {
    const Hash = std.crypto.hash.sha2.Sha256;
    var out: [Hash.digest_length * 2 + 1]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        &utils.hexToBytes(
            \\ed 1b 84 6b b9 26 39 00  c8 17 82 ad 08 eb 17 01
            \\fa 8c 72 21 c6 57 63 77  31 7f 5c e8 09 89 9f
        ),
        mgf1(Hash, "asdf", out[0 .. Hash.digest_length - 1]),
    );
    try std.testing.expectEqualSlices(
        u8,
        &utils.hexToBytes(
            \\ed 1b 84 6b b9 26 39 00  c8 17 82 ad 08 eb 17 01
            \\fa 8c 72 21 c6 57 63 77  31 7f 5c e8 09 89 9f 5a
            \\22 F2 80 D5 28 08 F4 93  83 76 00 DE 09 E4 EC 92
            \\4A 2C 7C EF 0D F7 7B BE  8F 7F 12 CB 8F 33 A6 65
            \\AB
        ),
        mgf1(Hash, "asdf", &out),
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
    _ = @import("rsa_test.zig");
}
