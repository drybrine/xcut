package com.drybrine.xcutandroid.crypto;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Minimal Ed25519 group arithmetic (extended coordinates) + sc_reduce, ported
 * to match BoringSSL semantics used by adb's SPAKE2. Pure JVM - no Android
 * dependencies, runnable in unit tests on desktop.
 */
public final class Ed25519Ops {
    private Ed25519Ops() {}

    public static final BigInteger P = BigInteger.ONE.shiftLeft(255)
            .subtract(new BigInteger("19"));
    // Order of the prime-order subgroup of curve25519 (Ed25519 group order)
    public static final BigInteger L = BigInteger.ONE.shiftLeft(252)
            .add(new BigInteger("27742317777372353535851937790883648493"));
    private static final BigInteger D = new BigInteger(
            "37095705934669439343138083508754565189542113879843219016388785533085940283555");
    private static final BigInteger D2 = D.multiply(BigInteger.TWO).mod(P);
    // sqrt(-1) mod p (p == 5 mod 8): 2^((p-1)/4)
    private static final BigInteger SQRT_M1 = BigInteger.TWO
            .modPow(P.subtract(BigInteger.ONE).shiftRight(2), P);

    public static final BigInteger GX = new BigInteger(
            "15112221349535400772501151409588531511454012693041857206046113283949847762202");
    public static final BigInteger GY = new BigInteger(
            "46316835694926478169428394003475163141307993866256225615783033603165251855960");

    // The two fixed SPAKE2 points from BoringSSL spake25519.cc comments
    public static final BigInteger MX = new BigInteger(
            "31406539342727633121250288103050113562375374900226415211311216773867585644232");
    public static final BigInteger MY = new BigInteger(
            "21177308356423958466833845032658859666296341766942662650232962324899758529114");
    public static final BigInteger NX = new BigInteger(
            "49918732221787544735331783592030787422991506689877079631459872391322455579424");
    public static final BigInteger NY = new BigInteger(
            "54629554431565467720832445949441049581317094546788069926228343916274969994000");

    private static final BigInteger[] M_POINT = {MX, MY};
    private static final BigInteger[] N_POINT = {NX, NY};

    private static final byte[] GENERATOR_ENCODED = hex(
            "5866666666666666666666666666666666666666666666666666666666666666");

    @SuppressWarnings("unused")
    private static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    public static byte[] sha512(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-512").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Little-endian 256-bit scalar reduction mod L (BoringSSL x25519_sc_reduce). */
    public static byte[] scReduce(byte[] in64) {
        if (in64.length != 64) throw new IllegalArgumentException("need 64 bytes");
        byte[] le = Arrays.copyOf(in64, 32);
        byte[] hi = Arrays.copyOfRange(in64, 32, 64);
        BigInteger v = fromLe(le).add(BigInteger.ONE.shiftLeft(256).multiply(fromLe(hi)))
                .mod(L);
        return toLe(v, 32);
    }

    public static BigInteger fromLe(byte[] b) {
        byte[] rev = new byte[b.length];
        for (int i = 0; i < b.length; i++) rev[i] = b[b.length - 1 - i];
        return new BigInteger(1, rev);
    }

    public static byte[] toLe(BigInteger v, int len) {
        byte[] be = v.toByteArray();
        byte[] out = new byte[len];
        int start = Math.max(0, be.length - len);
        for (int i = 0; i < be.length - start; i++) {
            out[i] = be[be.length - 1 - i];
        }
        return out;
    }

    // ---- point arithmetic on extended coordinates (X, Y, Z, T), T = XY/Z ----

    private static BigInteger mod(BigInteger v) {
        BigInteger r = v.mod(P);
        return r.signum() < 0 ? r.add(P) : r;
    }

    /** Decode a 32-byte Ed25519 point (BoringSSL x25519_ge_frombytes). Returns null if invalid. */
    public static BigInteger[] decodePoint(byte[] in) {
        if (in.length != 32) return null;
        byte[] yb = Arrays.copyOf(in, 32);
        int sign = (yb[31] >> 7) & 1;
        yb[31] &= 0x7f;
        BigInteger y = fromLe(yb);
        if (y.compareTo(P) >= 0) return null;
        BigInteger y2 = y.multiply(y).mod(P);
        // x^2 = (y^2 - 1) / (d y^2 + 1)
        BigInteger u = y2.subtract(BigInteger.ONE).mod(P);
        BigInteger v = D.multiply(y2).add(BigInteger.ONE).mod(P);
        if (v.signum() == 0) return null;
        // sqrt(u/v): r = (u*v)^((p+3)/8), x = r * v^-1; r^2 = +/- u*v
        BigInteger t = u.multiply(v).mod(P);
        BigInteger r = t.modPow(P.add(BigInteger.valueOf(3)).shiftRight(3), P);
        BigInteger vInv = v.modInverse(P);
        BigInteger x = mod(r.multiply(vInv));
        // ref10: if x^2*v == -u, multiply by sqrt(-1) so x^2*v == u
        BigInteger negU = mod(u.negate());
        if (x.multiply(x).multiply(v).mod(P).compareTo(negU) == 0) {
            x = mod(x.multiply(SQRT_M1));
        }
        // enforce the sign bit; flipping x keeps x^2*v == u
        if ((x.testBit(0) ? 1 : 0) != sign) x = mod(x.negate());
        return new BigInteger[]{x, y};
    }

    /** sqrt mod p for p == 5 (mod 8), returns 0 if a is a non-square (0 -> sqrt chain). */
    private static BigInteger sqrtMod(BigInteger a) {
        BigInteger a_mod = a.mod(P);
        BigInteger r = a_mod.modPow(P.add(BigInteger.valueOf(3)).shiftRight(3), P);
        // verify
        if (r.multiply(r).mod(P).compareTo(a_mod) == 0) return r;
        return BigInteger.ZERO;
    }

    public static byte[] encodePoint(BigInteger[] pt) {
        BigInteger z = mod(pt[2]);
        if (z.signum() == 0) throw new IllegalArgumentException("point at infinity");
        BigInteger zi = z.modInverse(P);
        BigInteger x = mod(pt[0].multiply(zi));
        BigInteger y = mod(pt[1].multiply(zi));
        byte[] out = toLe(y, 32);
        if (x.testBit(0)) out[31] |= 0x80;
        return out;
    }

    private static BigInteger[] addPts(BigInteger[] p, BigInteger[] q, boolean subtract) {
        BigInteger x1 = mod(p[0]), y1 = mod(p[1]), z1 = mod(p[2]), t1 = mod(p[3]);
        BigInteger x2 = mod(q[0]), y2 = mod(q[1]), z2 = mod(q[2]), t2 = mod(q[3]);
        if (subtract) {
            // P - Q = P + (-Q), with -Q = (-x, y) i.e. negate X and T
            x2 = mod(x2.negate());
            t2 = mod(t2.negate());
        }
        BigInteger a = mod(y1.subtract(x1).multiply(y2.subtract(x2)));
        BigInteger b = mod(y1.add(x1).multiply(y2.add(x2)));
        BigInteger c = mod(D2.multiply(t1).multiply(t2));
        BigInteger d = mod(BigInteger.TWO.multiply(z1).multiply(z2));
        BigInteger e = mod(b.subtract(a));
        BigInteger f = mod(d.subtract(c));
        BigInteger g = mod(d.add(c));
        BigInteger h = mod(b.add(a));
        return new BigInteger[]{
                mod(e.multiply(f)), mod(g.multiply(h)),
                mod(f.multiply(g)), mod(e.multiply(h)),
        };
    }

    public static BigInteger[] add(BigInteger[] p, BigInteger[] q) { return addPts(p, q, false); }
    public static BigInteger[] sub(BigInteger[] p, BigInteger[] q) { return addPts(p, q, true); }

    /** Convert affine (x, y) to extended. */
    public static BigInteger[] toExtended(BigInteger x, BigInteger y) {
        BigInteger xm = mod(x), ym = mod(y);
        return new BigInteger[]{xm, ym, BigInteger.ONE, mod(xm.multiply(ym))};
    }

    /** Scalar multiplication: scalar * point (double-and-add, complete formula). */
    public static BigInteger[] scalarMult(BigInteger scalar, BigInteger[] point) {
        byte[] s = toLe(scalar.mod(L), 32);
        BigInteger[] result = toExtended(BigInteger.ZERO, BigInteger.ONE); // identity
        for (int i = 255; i >= 0; i--) {
            result = add(result, result); // double
            if (((s[i / 8] >> (i % 8)) & 1) == 1) {
                result = add(result, point);
            }
        }
        return result;
    }

    public static BigInteger[] scalarmultBase(BigInteger scalar) {
        return scalarMult(scalar, toExtended(GX, GY));
    }

    public static BigInteger[] scalarmultM(BigInteger scalar) {
        return scalarMult(scalar, toExtended(MX, MY));
    }

    public static BigInteger[] scalarmultN(BigInteger scalar) {
        return scalarMult(scalar, toExtended(NX, NY));
    }

    /** Shortcut used by tests: check x,y of a point against expected affine coords. */
    public static boolean affineEquals(BigInteger[] ext, BigInteger x, BigInteger y) {
        BigInteger z = mod(ext[2]);
        if (z.signum() == 0) return false;
        BigInteger zi = z.modInverse(P);
        return mod(ext[0].multiply(zi)).compareTo(mod(x)) == 0
                && mod(ext[1].multiply(zi)).compareTo(mod(y)) == 0;
    }
}