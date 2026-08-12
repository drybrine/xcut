package com.drybrine.xcutandroid.crypto;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Port of BoringSSL spake25519.cc (SPAKE2 over Edwards25519, the variant used
 * by Android wireless-debugging pairing). Includes the "password scalar hack"
 * (cofactor clearing compensation).
 */
public final class Spake2 {

    public static final int MSG_SIZE = 32;
    public static final int MAX_KEY_SIZE = 64;

    // Note: adb passes sizeof(kClientName) which INCLUDES the trailing NUL
    public static final byte[] CLIENT_NAME = "adb pair client\u0000".getBytes();
    public static final byte[] SERVER_NAME = "adb pair server\u0000".getBytes();

    public enum Role { ALICE, BOB }

    public static final class Ctx {
        final Role role;
        final byte[] myName;
        final byte[] theirName;
        byte[] privateKey;      // 32 bytes, multiple of 8
        byte[] passwordHash;    // SHA-512(password)
        byte[] passwordScalar;  // 32 bytes LE, multiple of 8
        byte[] myMsg;           // 32 bytes
        boolean msgGenerated;
        final SecureRandom rng;

        Ctx(Role role, byte[] myName, byte[] theirName, SecureRandom rng) {
            this.role = role;
            this.myName = myName;
            this.theirName = theirName;
            this.rng = rng;
        }
    }

    public static Ctx newContext(Role role, byte[] myName, byte[] theirName) {
        return new Ctx(role, myName, theirName, new SecureRandom());
    }

    /** BoringSSL SPAKE2_generate_msg. Returns the 32-byte SPAKE2 message. */
    public static byte[] generateMsg(Ctx ctx, byte[] password) {
        if (ctx.msgGenerated) throw new IllegalStateException("msg already generated");
        byte[] privateTmp = new byte[64];
        ctx.rng.nextBytes(privateTmp);
        byte[] scalar = Ed25519Ops.scReduce(privateTmp);
        leftShift3(scalar);
        ctx.privateKey = scalar;

        // mask = h(password) * <M if Alice else N>
        byte[] passwordHash = Ed25519Ops.sha512(password);
        ctx.passwordHash = passwordHash;
        byte[] pwTmp = Ed25519Ops.scReduce(passwordHash);
        byte[] pwScalar = fixPasswordScalar(pwTmp);
        ctx.passwordScalar = pwScalar;

        BigInteger[] p = Ed25519Ops.scalarmultBase(Ed25519Ops.fromLe(ctx.privateKey));
        BigInteger[] mask = ctx.role == Role.ALICE
                ? Ed25519Ops.scalarmultM(Ed25519Ops.fromLe(pwScalar))
                : Ed25519Ops.scalarmultN(Ed25519Ops.fromLe(pwScalar));
        BigInteger[] pstar = Ed25519Ops.add(p, mask);
        ctx.myMsg = Ed25519Ops.encodePoint(pstar);
        ctx.msgGenerated = true;
        return ctx.myMsg;
    }

    /**
     * BoringSSL SPAKE2_process_msg. Returns the shared key material (64 bytes),
     * or null if the peer message was invalid.
     */
    public static byte[] processMsg(Ctx ctx, byte[] theirMsg) {
        if (!ctx.msgGenerated || theirMsg.length != MSG_SIZE) return null;
        BigInteger[] qstar = Ed25519Ops.decodePoint(theirMsg);
        if (qstar == null) return null;

        BigInteger[] peersMask = ctx.role == Role.ALICE
                ? Ed25519Ops.scalarmultN(Ed25519Ops.fromLe(ctx.passwordScalar))
                : Ed25519Ops.scalarmultM(Ed25519Ops.fromLe(ctx.passwordScalar));
        // scalarmult returns projective coords (Z != 1); affinize before use
        BigInteger maskZi = peersMask[2].mod(Ed25519Ops.P).modInverse(Ed25519Ops.P);
        BigInteger maskX = peersMask[0].multiply(maskZi).mod(Ed25519Ops.P);
        BigInteger maskY = peersMask[1].multiply(maskZi).mod(Ed25519Ops.P);
        BigInteger[] q = Ed25519Ops.sub(
                Ed25519Ops.toExtended(qstar[0], qstar[1]),
                Ed25519Ops.toExtended(maskX, maskY));

        BigInteger[] dh = Ed25519Ops.scalarMult(Ed25519Ops.fromLe(ctx.privateKey), q);
        byte[] dhEncoded = Ed25519Ops.encodePoint(dh);

        // transcript: SHA-512 of 8-byte LE length-prefixed fields
        java.security.MessageDigest sha;
        try {
            sha = java.security.MessageDigest.getInstance("SHA-512");
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        if (ctx.role == Role.ALICE) {
            updatePrefix(sha, ctx.myName);
            updatePrefix(sha, ctx.theirName);
            updatePrefix(sha, ctx.myMsg);
            updatePrefix(sha, theirMsg);
        } else {
            updatePrefix(sha, ctx.theirName);
            updatePrefix(sha, ctx.myName);
            updatePrefix(sha, theirMsg);
            updatePrefix(sha, ctx.myMsg);
        }
        updatePrefix(sha, dhEncoded);
        updatePrefix(sha, ctx.passwordHash);
        byte[] key = sha.digest();
        return key.length > MAX_KEY_SIZE ? Arrays.copyOf(key, MAX_KEY_SIZE) : key;
    }

    private static void updatePrefix(java.security.MessageDigest sha, byte[] data) {
        byte[] len = new byte[8];
        long l = data.length;
        for (int i = 0; i < 8; i++) {
            len[i] = (byte) (l & 0xff);
            l >>= 8;
        }
        sha.update(len);
        sha.update(data);
    }

    /** left_shift_3: n = n * 8 in place (plain shift, no mod). */
    private static void leftShift3(byte[] n) {
        int carry = 0;
        for (int i = 0; i < 32; i++) {
            int nc = (n[i] & 0xff) >> 5;
            n[i] = (byte) (((n[i] & 0xff) << 3) | carry);
            carry = nc;
        }
    }

    /**
     * The BoringSSL password-scalar hack: add l, 2*l, 4*l so the scalar is a
     * multiple of 8 (cancels small-order points of the peer, clearing the
     * cofactor without "leaking" the password hash bits).
     */
    private static byte[] fixPasswordScalar(byte[] reduced) {
        BigInteger order = Ed25519Ops.L;
        BigInteger v = Ed25519Ops.fromLe(reduced);
        // Each cmov/add step in BoringSSL re-checks the *current* value's bit
        // (adding l flips bit 0, adding 2*l flips bit 1, adding 4*l flips bit 2).
        if (v.testBit(0)) v = v.add(order);
        if (v.testBit(1)) v = v.add(order.shiftLeft(1));
        if (v.testBit(2)) v = v.add(order.shiftLeft(2));
        if (v.testBit(0) || v.testBit(1) || v.testBit(2)) {
            throw new IllegalStateException("password scalar hack failed");
        }
        return Ed25519Ops.toLe(v, 32);
    }
}