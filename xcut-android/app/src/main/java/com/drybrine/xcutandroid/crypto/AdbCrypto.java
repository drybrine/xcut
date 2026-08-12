package com.drybrine.xcutandroid.crypto;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Support crypto for the adb wireless-debugging flow: HKDF, the AES-128-GCM
 * pairing cipher, RSA keys, adb authorized-keys lines, and self-signed certs.
 */
public final class AdbCrypto {
    private AdbCrypto() {}

    public static final String HKDF_INFO_PAIRING =
            "adb pairing_auth aes-128-gcm key";

    // ---------------- HKDF-SHA256 ----------------

    public static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int length) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            byte[] prk;
            if (salt == null || salt.length == 0) {
                mac.init(new SecretKeySpec(new byte[32], "HmacSHA256"));
                prk = mac.doFinal(ikm);
            } else {
                mac.init(new SecretKeySpec(salt, "HmacSHA256"));
                prk = mac.doFinal(ikm);
            }
            byte[] okm = new byte[length];
            byte[] t = new byte[0];
            int pos = 0;
            byte counter = 1;
            while (pos < length) {
                mac.init(new SecretKeySpec(prk, "HmacSHA256"));
                mac.update(t);
                mac.update(info);
                mac.update(counter++);
                t = mac.doFinal();
                int n = Math.min(t.length, length - pos);
                System.arraycopy(t, 0, okm, pos, n);
                pos += n;
            }
            return okm;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    // ---------------- AES-128-GCM (adb pairing cipher) ----------------

    /** 12-byte nonce: 4-byte little-endian sequence counter + 8 zero bytes. */
    public static byte[] gcmNonce(int sequence) {
        byte[] nonce = new byte[12];
        nonce[0] = (byte) (sequence & 0xff);
        nonce[1] = (byte) ((sequence >> 8) & 0xff);
        nonce[2] = (byte) ((sequence >> 16) & 0xff);
        nonce[3] = (byte) ((sequence >> 24) & 0xff);
        return nonce;
    }

    public static byte[] gcmEncrypt(byte[] key16, int sequence, byte[] plaintext) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key16, "AES"),
                    new GCMParameterSpec(128, gcmNonce(sequence)));
            return cipher.doFinal(plaintext);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static byte[] gcmDecrypt(byte[] key16, int sequence, byte[] ciphertext) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key16, "AES"),
                    new GCMParameterSpec(128, gcmNonce(sequence)));
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    // ---------------- RSA / adb key handling ----------------

    public static KeyPair generateRsaKey() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048, new SecureRandom());
            return kpg.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** Build the adb authorized-keys line: "ssh-rsa <base64> <comment>". */
    public static String userKeyLine(RSAPublicKey pub) {
        byte[] blob = sshRsaBlob(pub);
        return "ssh-rsa " + java.util.Base64.getEncoder().encodeToString(blob)
                + " xcut@local";
    }

    /** SSH-format public key blob: string "ssh-rsa", mpint e, mpint n. */
    public static byte[] sshRsaBlob(RSAPublicKey pub) {
        byte[] type = "ssh-rsa".getBytes(StandardCharsets.UTF_8);
        byte[] e = unsignedBigEndian(pub.getPublicExponent());
        byte[] n = unsignedBigEndian(pub.getModulus());
        byte[] out = new byte[4 + type.length + 4 + e.length + 4 + n.length];
        int p = 0;
        p = putLen(out, p, type.length);
        System.arraycopy(type, 0, out, p, type.length);
        p += type.length;
        p = putLen(out, p, e.length);
        System.arraycopy(e, 0, out, p, e.length);
        p += e.length;
        p = putLen(out, p, n.length);
        System.arraycopy(n, 0, out, p, n.length);
        return out;
    }

    private static int putLen(byte[] out, int p, int len) {
        out[p++] = (byte) (len >> 24);
        out[p++] = (byte) (len >> 16);
        out[p++] = (byte) (len >> 8);
        out[p++] = (byte) len;
        return p;
    }

    private static byte[] unsignedBigEndian(java.math.BigInteger v) {
        byte[] raw = v.toByteArray();
        int off = (raw.length > 1 && raw[0] == 0) ? 1 : 0;
        return Arrays.copyOfRange(raw, off, raw.length);
    }

    /** RSA PKCS#1 v1.5 SHA-1 signature - the adb auth token signature. */
    public static byte[] rsaSha1Sign(PrivateKey key, byte[] token) {
        try {
            Signature sig = Signature.getInstance("SHA1withRSA");
            sig.initSign(key);
            sig.update(token);
            return sig.sign();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static PrivateKey pkcs8Private(byte[] der) {
        try {
            return KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static PublicKey x509Public(byte[] der) {
        try {
            return KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(der));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static byte[] encodePublicKey(PublicKey pub) {
        return pub.getEncoded();
    }

    // ---------------- self-signed X.509 (pairing/connect TLS) ----------------

    /**
     * Hand-rolled DER for a minimal self-signed X.509 cert (CN=adb). The adbd
     * pairing/connect TLS trusts any peer certificate, so the exact BER
     * choices only need to be parseable by Android's CertificateFactory.
     */
    public static X509Certificate selfSignedCert(KeyPair kp) {
        try {
            RSAPublicKey pub = (RSAPublicKey) kp.getPublic();
            byte[] rsaPub = derSequence(intBytes(pub.getModulus()), intBytes(pub.getPublicExponent()));
            byte[] spki = derSequence(
                    derSequence(oid("1.2.840.113549.1.1.1"), derNull()),
                    derBitString(rsaPub));
            long now = System.currentTimeMillis();
            String notBefore = utcTime(now - 86400000L);
            String notAfter = utcTime(now + 365L * 86400000L * 5);
            byte[] name = derSequence(              // RDNSequence
                    derSet(derSequence(oid("2.5.4.3"), utf8("adb"))));
            byte[] validity = derSequence(ascii(notBefore), ascii(notAfter));
            byte[] basicConstraints = derOctetString(derSequence()); // CA=false
            byte[] extensions = derSequence(derSequence(oid("2.5.29.19"), boolTrue(),
                    basicConstraints));
            byte[] tbs = derSequence(
                    derContext(0, derInteger(java.math.BigInteger.valueOf(2))), // v3
                    derInteger(serial()),
                    algIdSha256Rsa(),
                    name,                                     // issuer
                    validity,
                    name,                                     // subject
                    spki,
                    derContext(3, extensions));
            byte[] sig = sign("SHA256withRSA", kp.getPrivate(), tbs);
            byte[] certDer = derSequence(tbs, algIdSha256Rsa(),
                    derBitString(sig));
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(
                    new java.io.ByteArrayInputStream(certDer));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] algIdSha256Rsa() {
        return derSequence(oid("1.2.840.113549.1.1.11"), derNull());
    }

    private static byte[] sign(String algo, PrivateKey key, byte[] data) {
        try {
            Signature s = Signature.getInstance(algo);
            s.initSign(key);
            s.update(data);
            return s.sign();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static java.math.BigInteger serial() {
        return new java.math.BigInteger(64, new SecureRandom());
    }

    private static byte[] derInteger(java.math.BigInteger v) {
        return der(0x02, v.toByteArray());
    }

    private static String utcTime(long millis) {
        java.text.SimpleDateFormat fmt =
                new java.text.SimpleDateFormat("yyMMddHHmmss'Z'", java.util.Locale.US);
        fmt.setTimeZone(java.util.TimeZone.getTimeZone("UTC"));
        return fmt.format(new java.util.Date(millis));
    }

    // ---------------- minimal DER helpers ----------------

    private static byte[] oid(String dotted) {
        String[] parts = dotted.split("\\.");
        long[] v = new long[parts.length];
        for (int i = 0; i < parts.length; i++) v[i] = Long.parseLong(parts[i]);
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        out.write((int) (v[0] * 40 + v[1]));
        for (int i = 2; i < v.length; i++) writeBase128(out, v[i]);
        return der(0x06, out.toByteArray());
    }

    private static void writeBase128(java.io.ByteArrayOutputStream out, long val) {
        byte[] tmp = new byte[10];
        int i = tmp.length;
        tmp[--i] = (byte) (val & 0x7f);
        while ((val >>= 7) != 0) tmp[--i] = (byte) ((val & 0x7f) | 0x80);
        out.write(tmp, i, tmp.length - i);
    }

    private static byte[] intBytes(java.math.BigInteger v) {
        byte[] raw = v.toByteArray();
        return der(0x02, raw);
    }

    private static byte[] derInteger(long v) {
        return der(0x02, new java.math.BigInteger(Long.toString(v)).toByteArray());
    }

    private static byte[] derNull() { return new byte[]{0x05, 0x00}; }
    private static byte[] boolTrue() { return new byte[]{0x01, 0x01, (byte) 0xff}; }

    private static byte[] utf8(String s) { return der(0x0c, s.getBytes(StandardCharsets.UTF_8)); }
    private static byte[] ascii(String s) { return der(0x17, s.getBytes(StandardCharsets.US_ASCII)); }
    private static byte[] derOctetString(byte[] inner) { return der(0x04, inner); }
    private static byte[] derBitString(byte[] inner) {
        byte[] body = new byte[inner.length + 1];
        body[0] = 0;
        System.arraycopy(inner, 0, body, 1, inner.length);
        return der(0x03, body);
    }

    private static byte[] der(Integer tag, byte[] body) {
        int lenBytes;
        if (body.length < 128) {
            lenBytes = 1;
        } else if (body.length < 256) {
            lenBytes = 2;
        } else {
            lenBytes = 3;
        }
        byte[] out = new byte[body.length + 1 + lenBytes];
        out[0] = tag.byteValue();
        if (lenBytes == 1) {
            out[1] = (byte) body.length;
        } else if (lenBytes == 2) {
            out[1] = (byte) 0x81;
            out[2] = (byte) body.length;
        } else {
            out[1] = (byte) 0x82;
            out[2] = (byte) (body.length >> 8);
            out[3] = (byte) body.length;
        }
        System.arraycopy(body, 0, out, 1 + lenBytes, body.length);
        return out;
    }

    private static byte[] derContext(int n, byte[] body) {
        byte[] out = new byte[body.length + 2];
        out[0] = (byte) (0xa0 | n);
        out[1] = (byte) body.length;
        System.arraycopy(body, 0, out, 2, body.length);
        return out;
    }

    private static byte[] derSequence(byte[]... parts) {
        int total = 0;
        for (byte[] p : parts) total += p.length;
        byte[] body = new byte[total];
        int p = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, body, p, part.length);
            p += part.length;
        }
        return der(0x30, body);
    }

    private static byte[] derSet(byte[] inner) { return der(0x31, inner); }
}