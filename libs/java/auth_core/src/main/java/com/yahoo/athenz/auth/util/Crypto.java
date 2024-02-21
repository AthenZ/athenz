/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.yahoo.athenz.auth.util;

import java.io.*;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;
import java.util.function.Function;

import javax.security.auth.x500.X500Principal;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemObject;

public class Crypto {

    private static final Logger LOG = LoggerFactory.getLogger(Crypto.class);
    static final String ATHENZ_CRYPTO_ALGO_RSA = "athenz.crypto.algo_rsa";
    private static final String RSA = "RSA";
    private static final String RSA_SHA1 = "SHA1withRSA";
    private static final String RSA_SHA256 = "SHA256withRSA";
    static final String ATHENZ_CRYPTO_ALGO_ECDSA = "athenz.crypto.algo_ecdsa";
    private static final String EC = "EC";
    private static final String ECDSA = "ECDSA";
    private static final String ECDSA_SHA1 = "SHA1withECDSA";
    private static final String ECDSA_SHA256 = "SHA256withECDSA";

    public static final String SHA1 = "SHA1";
    public static final String SHA256 = "SHA256";
    public static final String SHA384 = "SHA384";
    public static final String SHA512 = "SHA512";

    static final String ATHENZ_CRYPTO_KEY_FACTORY_PROVIDER = "athenz.crypto.key_factory_provider";
    static final String ATHENZ_CRYPTO_SIGNATURE_PROVIDER = "athenz.crypto.signature_provider";
    private static final String BC_PROVIDER = "BC";

    public static final String CERT_RESTRICTED_SUFFIX = ":restricted";
    public static final String CERT_SPIFFE_URI = "spiffe://";

    static final SecureRandom RANDOM;
    static final ObjectMapper JSON_MAPPER;
    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        SecureRandom r;
        try {
            r = SecureRandom.getInstance("NativePRNGNonBlocking");
        } catch (NoSuchAlgorithmException nsa) {
            r = new SecureRandom();
        }
        RANDOM = r;
        // force seeding.
        RANDOM.nextBytes(new byte[] { 8 });

        JSON_MAPPER = new ObjectMapper();
        JSON_MAPPER.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    private static String getKeyFactoryProvider() {
        return System.getProperty(ATHENZ_CRYPTO_KEY_FACTORY_PROVIDER, BC_PROVIDER);
    }

    private static String getSignatureProvider() {
        return System.getProperty(ATHENZ_CRYPTO_SIGNATURE_PROVIDER, BC_PROVIDER);
    }

    private static String getECDSAAlgo() {
        return System.getProperty(ATHENZ_CRYPTO_ALGO_ECDSA, ECDSA);
    }

    private static String getRSAAlgo() {
        return System.getProperty(ATHENZ_CRYPTO_ALGO_RSA, RSA);
    }

    public static String getDigestAlgorithm(final String algorithm) {
        String digestAlgorithm = null;
        switch (algorithm) {
            case "ES256":
            case "RS256":
                digestAlgorithm = SHA256;
                break;
            case "ES384":
            case "RS384":
                digestAlgorithm = SHA384;
                break;
            case "ES512":
            case "RS512":
                digestAlgorithm = SHA512;
                break;
        }
        return digestAlgorithm;
    }

    public static int getSignatureExpectedSize(final String algorithm) {
        int size = 0;
        switch (algorithm) {
            case SHA256:
                size = 32;
                break;
            case SHA384:
                size = 48;
                break;
            case SHA512:
                size = 66;
                break;
        }
        return size;
    }

    /**
     * Sign the message with the shared secret using HmacSHA256
     * The result is a ybase64 (url safe) string.
     * @param message the UTF-8 string to be signed
     * @param sharedSecret the secret to sign with
     * @return the ybase64 representation of the signature.
     * @throws CryptoException for any issues with provider/algorithm/signature/key
     */
    public static String hmac(String message, String sharedSecret) throws CryptoException {
        //this has not been optimized!
        String method = "HmacSHA256";
        byte [] bsig;
        try {
            javax.crypto.Mac hmac = javax.crypto.Mac.getInstance(method);
            javax.crypto.spec.SecretKeySpec secretKey = new javax.crypto.spec.SecretKeySpec(utf8Bytes(sharedSecret), method);
            hmac.init(secretKey);
            bsig = hmac.doFinal(message.getBytes());
        } catch (NoSuchAlgorithmException e) {
            LOG.error("hmac: Caught NoSuchAlgorithmException, check to make sure the algorithm is supported by the provider.");
            throw new CryptoException(e);
        } catch (InvalidKeyException e) {
            LOG.error("hmac: Caught InvalidKeyException, incorrect key type is being used.");
            throw new CryptoException(e);
        }
        return ybase64(bsig);
    }

    static String getSignatureAlgorithm(String keyAlgorithm) throws NoSuchAlgorithmException {
        return getSignatureAlgorithm(keyAlgorithm, SHA256);
    }

    static String getSignatureAlgorithm(String keyAlgorithm, String digestAlgorithm) throws NoSuchAlgorithmException {
        String signatureAlgorithm = null;
        switch (keyAlgorithm) {
            case RSA:
                if (SHA256.equals(digestAlgorithm)) {
                    signatureAlgorithm = RSA_SHA256;
                } else if (SHA1.equals(digestAlgorithm)) {
                    signatureAlgorithm = RSA_SHA1;
                }
                break;
            case ECDSA:
            case EC:
                if (SHA256.equals(digestAlgorithm)) {
                    signatureAlgorithm = ECDSA_SHA256;
                } else if (SHA1.equals(digestAlgorithm)) {
                    signatureAlgorithm = ECDSA_SHA1;
                }
                break;
        }

        if (signatureAlgorithm == null) {
            LOG.error("getSignatureAlgorithm: Unknown key algorithm: {} digest algorithm: {}",
                    keyAlgorithm, digestAlgorithm);
            throw new NoSuchAlgorithmException();
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Signature Algorithm: {}", signatureAlgorithm);
        }

        return signatureAlgorithm;
    }

    /**
     * Sign the text with given digest algorithm and private key. Returns the ybase64 encoding of it.
     * @param message the message to sign, as a UTF8 string
     * @param key the private key to sign with
     * @param digestAlgorithm supported values SHA1 and SHA256
     * @return the ybase64 encoded signature for the data
     * @throws CryptoException for any issues with provider/algorithm/signature/key
     */
    public static String sign(String message, PrivateKey key, String digestAlgorithm) throws CryptoException {
        try {
            String signatureAlgorithm = getSignatureAlgorithm(key.getAlgorithm(), digestAlgorithm);
            java.security.Signature signer = java.security.Signature.getInstance(signatureAlgorithm, getSignatureProvider());
            signer.initSign(key);
            signer.update(utf8Bytes(message));
            byte[] sig = signer.sign();
            return ybase64(sig);
        } catch (NoSuchProviderException e) {
            LOG.error("sign: Caught NoSuchProviderException, check to make sure the provider is loaded correctly.");
            throw new CryptoException(e);
        } catch (NoSuchAlgorithmException e) {
            LOG.error("sign: Caught NoSuchAlgorithmException, check to make sure the algorithm is supported by the provider.");
            throw new CryptoException(e);
        } catch (SignatureException e) {
            LOG.error("sign: Caught SignatureException.");
            throw new CryptoException(e);
        } catch (InvalidKeyException e) {
            LOG.error("sign: Caught InvalidKeyException, incorrect key type is being used.");
            throw new CryptoException(e);
        }
    }

    /**
     * Sign the byte array with given digest algorithm and private key. Returns the byte array
     * @param message the message to sign, as a byte array
     * @param key the private key to sign with
     * @param digestAlgorithm supported values SHA1 and SHA256
     * @return the byte[] signature for the data
     * @throws CryptoException for any issues with provider/algorithm/signature/key
     */
    public static byte[] sign(byte[] message, PrivateKey key, String digestAlgorithm) throws CryptoException {
        try {
            String signatureAlgorithm = getSignatureAlgorithm(key.getAlgorithm(), digestAlgorithm);
            java.security.Signature signer = java.security.Signature.getInstance(signatureAlgorithm, getSignatureProvider());
            signer.initSign(key);
            signer.update(message);
            return signer.sign();
        } catch (NoSuchProviderException e) {
            LOG.error("sign: Caught NoSuchProviderException, check to make sure the provider is loaded correctly.");
            throw new CryptoException(e);
        } catch (NoSuchAlgorithmException e) {
            LOG.error("sign: Caught NoSuchAlgorithmException, check to make sure the algorithm is supported by the provider.");
            throw new CryptoException(e);
        } catch (SignatureException e) {
            LOG.error("sign: Caught SignatureException.");
            throw new CryptoException(e);
        } catch (InvalidKeyException e) {
            LOG.error("sign: Caught InvalidKeyException, incorrect key type is being used.");
            throw new CryptoException(e);
        }
    }

    public static byte[] convertSignatureFromP1363ToDERFormat(byte[] signature, final String digestAlgorithm) {

        int size = getSignatureExpectedSize(digestAlgorithm);
        if (size == 0) {
            LOG.error("unable to determine expected signature size for algorithm: {}", digestAlgorithm);
            throw new CryptoException("unknown signature size");
        }

        // the size of our buffer must twice the size of determined value

        if (signature.length != 2 * size) {
            LOG.error("unexpected signature size: {}, expected: {}", signature.length, 2 * size);
            throw new CryptoException("invalid signature size");
        }

        // generate our big integers

        BigInteger r = new BigInteger(1, Arrays.copyOfRange(signature, 0, size));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(signature, size, 2 * size));

        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new ASN1Integer(r));
        vector.add(new ASN1Integer(s));

        try {
            return new DERSequence(vector).getEncoded();
        } catch (Exception ex) {
            LOG.error("unable to generate der sequence", ex);
            throw new CryptoException("unable to convert to der format");
        }
    }

    /**
     * Convert signature byte array from ASN.1 DER format to P1363 Format
     * @param signature byte array in DER format
     * @param digestAlgorithm supported values e.g. SHA256
     * @return the byte[] signature in P1363 format
     * @throws CryptoException for any issues with provider/algorithm/signature/key
     */
    public static byte[] convertSignatureFromDERToP1363Format(byte[] signature, final String digestAlgorithm) {

        // first get the expected size for the supported digest algorithms

        int size = getSignatureExpectedSize(digestAlgorithm);
        if (size == 0) {
            LOG.error("unable to determine expected signature size for algorithm: {}", digestAlgorithm);
            throw new CryptoException("unknown signature size");
        }

        ASN1Sequence seq;
        try {
            seq = ASN1Sequence.getInstance(signature);
        } catch (Exception ex) {
            LOG.error("failed to construct asn1 sequence from signature", ex);
            throw new CryptoException("failed to construct asn1 sequence");
        }

        if (seq.size() != 2) {
            LOG.error("asn1 sequence does not have expected 2 integers: {}", seq.size());
            throw new CryptoException("invalid asn1sequence size");
        }
        BigInteger r = ((ASN1Integer) seq.getObjectAt(0)).getValue();
        BigInteger s = ((ASN1Integer) seq.getObjectAt(1)).getValue();

        // generate our output data that would be
        // twice the size of our expected value

        byte[] out = new byte[2 * size];
        safeCopyByteArray(toIntegerBytes(r, true), out, 0, size);
        safeCopyByteArray(toIntegerBytes(s, true), out, size, size);
        return out;
    }

    static void safeCopyByteArray(byte[] src, byte[] dest, int destPos, int length) {

        // if the length of the source byte array is smaller than what
        // want to copy we'll pad the preceding bytes with 0s
        int idxDestPos = destPos + length - src.length;
        if (src.length < length) {
            Arrays.fill(dest, destPos, idxDestPos, (byte) 0);
        }
        System.arraycopy(src, 0, dest, idxDestPos, src.length);
    }

    /**
     * <a href="https://github.com/apache/commons-codec/blob/master/src/main/java/org/apache/commons/codec/binary/Base64.java">https://github.com/apache/commons-codec/blob/master/src/main/java/org/apache/commons/codec/binary/Base64.java</a>
     * Licensed Under Apache 2.0 <a href="https://github.com/apache/commons-codec/blob/master/LICENSE.txt">https://github.com/apache/commons-codec/blob/master/LICENSE.txt</a>
     *
     * In apache.commons.code this is a private static function and the wrapper
     * does not generate base64 encoded data that is url safe which is required
     * per jwk spec. So we'll copy the function as is for our use.
     *
     * Returns a byte-array representation of a {@code BigInteger} without sign bit.
     *
     * @param bigInt {@code BigInteger} to be converted
     * @param skipSignBit support handling of sign bit based on spec (should be true)
     * @return a byte array representation of the BigInteger parameter
     */
    public static byte[] toIntegerBytes(final BigInteger bigInt, boolean skipSignBit) {

        // this will be removed once all properties update
        // their code to handle the sign bit correctly
        if (!skipSignBit) {
            return bigInt.toByteArray();
        }

        int bitlen = bigInt.bitLength();
        // round bitlen
        bitlen = ((bitlen + 7) >> 3) << 3;
        final byte[] bigBytes = bigInt.toByteArray();

        if (((bigInt.bitLength() % 8) != 0) && (((bigInt.bitLength() / 8) + 1) == (bitlen / 8))) {
            return bigBytes;
        }
        // set up params for copying everything but sign bit
        int startSrc = 0;
        int len = bigBytes.length;

        // if bigInt is exactly byte-aligned, just skip signbit in copy
        if ((bigInt.bitLength() % 8) == 0) {
            startSrc = 1;
            len--;
        }

        final int startDst = bitlen / 8 - len; // to pad w/ nulls as per spec
        final byte[] resizedBytes = new byte[bitlen / 8];
        System.arraycopy(bigBytes, startSrc, resizedBytes, startDst, len);
        return resizedBytes;
    }

    /**
     * Sign the text with SHA-256 and the private key. Returns the ybase64 encoding of it.
     * @param message the message to sign, as a UTF8 string
     * @param key the private key to sign with
     * @return the ybase64 encoded signature for the data
     * @throws CryptoException for any issues with provider/algorithm/signature/key
     */
    public static String sign(String message, PrivateKey key) throws CryptoException {
        return sign(message, key, SHA256);
    }

    /**
     * Verify the signed data with given digest algorithm and the private key against the ybase64 encoded signature.
     * @param message the message to sign, as a UTF8 string
     * @param key the public key corresponding to the signing key
     * @param signature the ybase64 encoded signature for the data
     * @param digestAlgorithm supported values SHA1 and SHA256
     * @return true if the message was indeed signed by the signature.
     * @throws CryptoException for any issues with provider/algorithm/signature/key
     */
    public static boolean verify(String message, PublicKey key, String signature,
                                 String digestAlgorithm) throws CryptoException {
        try {
            byte [] sig = ybase64Decode(signature);
            String signatureAlgorithm = getSignatureAlgorithm(key.getAlgorithm(), digestAlgorithm);
            java.security.Signature signer = java.security.Signature.getInstance(signatureAlgorithm, getSignatureProvider());
            signer.initVerify(key);
            signer.update(utf8Bytes(message));
            return signer.verify(sig);
        } catch (NoSuchProviderException e) {
            LOG.error("verify: Caught NoSuchProviderException, check to make sure the provider is loaded correctly.");
            throw new CryptoException(e);
        } catch (InvalidKeyException e) {
            LOG.error("verify: Caught InvalidKeyException, invalid key type is being used.");
            throw new CryptoException(e);
        } catch (NoSuchAlgorithmException e) {
            LOG.error("verify: Caught NoSuchAlgorithmException, check to make sure the algorithm is supported by the provider.");
            throw new CryptoException(e);
        } catch (SignatureException e) {
            LOG.error("verify: Caught SignatureException.");
            throw new CryptoException(e);
        }
    }

    /**
     * Verify the signed data with SHA-256 and private key against the ybase64 encoded signature.
     * @param message the message to sign, as a UTF8 string
     * @param key the public key corresponding to the signing key
     * @param signature the ybase64 encoded signature for the data
     * @return true if the message was indeed signed by the signature.
     * @throws CryptoException for any issues with provider/algorithm/signature/key
     */
    public static boolean verify(String message, PublicKey key, String signature) throws CryptoException {
        return verify(message, key, signature, SHA256);
    }

    /**
     * Verify the signed data with given digest algorithm and the private key against the given signature.
     * @param message the message to sign, as a byte[]
     * @param key the public key corresponding to the signing key
     * @param signature the signature for the data
     * @param digestAlgorithm supported values SHA1 and SHA256
     * @return true if the message was indeed signed by the signature.
     * @throws CryptoException for any issues with provider/algorithm/signature/key
     */
    public static boolean verify(byte[] message, PublicKey key, byte[] signature,
                                 String digestAlgorithm) throws CryptoException {
        try {
            String signatureAlgorithm = getSignatureAlgorithm(key.getAlgorithm(), digestAlgorithm);
            java.security.Signature signer = java.security.Signature.getInstance(signatureAlgorithm, getSignatureProvider());
            signer.initVerify(key);
            signer.update(message);
            return signer.verify(signature);
        } catch (NoSuchProviderException e) {
            LOG.error("verify: Caught NoSuchProviderException, check to make sure the provider is loaded correctly.");
            throw new CryptoException(e);
        } catch (InvalidKeyException e) {
            LOG.error("verify: Caught InvalidKeyException, invalid key type is being used.");
            throw new CryptoException(e);
        } catch (NoSuchAlgorithmException e) {
            LOG.error("verify: Caught NoSuchAlgorithmException, check to make sure the algorithm is supported by the provider.");
            throw new CryptoException(e);
        } catch (SignatureException e) {
            LOG.error("verify: Caught SignatureException.");
            throw new CryptoException(e);
        }
    }

    static String utf8String(byte [] b) {
        return new String(b, StandardCharsets.UTF_8);
    }

    static byte [] utf8Bytes(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    public static byte [] sha256(byte [] data) throws CryptoException {
        MessageDigest sha256;
        try {
            sha256 = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            LOG.error("sha256: Caught NoSuchAlgorithmException, check to make sure the algorithm is supported by the provider.");
            throw new CryptoException(e);
        }
        return sha256.digest(data);
    }

    public static byte [] sha256(String text) throws CryptoException {
        return sha256(utf8Bytes(text));
    }

    /**
     * ybase64 is url-safe base64 encoding, using Y's unique convention.
     * The industry standard urlsafe solution is ("+/=" =&gt; "-_.").
     * The Y! convention is ("+/=" =&gt; "._-").
     * @param data the data to encode
     * @return the ybase64-encoded data as a String
     */
    public static String ybase64(byte [] data) {
        return utf8String(YBase64.encode(data));
    }

    /**
     * ybase64 is url-safe base64 encoding, using Y's unique convention.
     * The industry standard urlsafe solution is ("+/=" =&gt; "-_.").
     * The Y! convention is ("+/=" =&gt; "._-").
     * @param b64 the ybase64-encoded data
     * @return the decoded data
     */
    public static byte [] ybase64Decode(String b64) {
        return YBase64.decode(utf8Bytes(b64));
    }

    public static String ybase64DecodeString(String b64) {
        return utf8String(ybase64Decode(b64));
    }

    public static String ybase64EncodeString(String str) {
        return utf8String(YBase64.encode(utf8Bytes(str)));
    }

    public static String x509CertificatesToPEM(X509Certificate[] x509Certs) throws CryptoException {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pw = new JcaPEMWriter(sw)) {
            for (X509Certificate x509Cert : x509Certs) {
                pw.writeObject(x509Cert);
            }
        } catch (IOException ex) {
            LOG.error("Unable to generate PEM output", ex);
            throw new CryptoException(ex);
        }
        return sw.toString();
    }

    public static X509Certificate[] loadX509Certificates(final String certsFile) throws CryptoException {

        File certFile = new File(certsFile);

        try (InputStream certStream  = new FileInputStream(certFile)) {
            final CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Collection<? extends Certificate> certs = cf.generateCertificates(certStream);
            if (certs.isEmpty()) {
                throw new CryptoException("Certificate file contains empty certificate or an invalid certificate.");
            }
            return certs.parallelStream().filter(X509Certificate.class::isInstance).toArray(X509Certificate[]::new);
        } catch (IOException ex) {
            LOG.error("loadX509Certificates: unable to process file: {}", certFile.getAbsolutePath());
            throw new CryptoException(ex);
        } catch (CertificateException ex) {
            LOG.error("Unable to load certificates", ex);
            throw new CryptoException(ex);
        }
    }

    public static X509Certificate loadX509Certificate(File certFile) throws CryptoException  {
        try (FileReader fileReader = new FileReader(certFile)) {
            return loadX509Certificate(fileReader);
        } catch (FileNotFoundException e) {
            LOG.error("loadX509Certificate: Caught FileNotFoundException while attempting to load certificate for file: {}",
                    certFile.getAbsolutePath());
            throw new CryptoException(e);
        } catch (IOException e) {
            LOG.error("loadX509Certificate: Caught IOException while attempting to load certificate for file: {}",
                    certFile.getAbsolutePath());
            throw new CryptoException(e);
        }
    }

    public static X509Certificate loadX509Certificate(String pemEncoded) throws CryptoException {
        return Crypto.loadX509Certificate(new StringReader(pemEncoded));
    }

    public static X509Certificate loadX509Certificate(Reader reader) throws CryptoException {
        try (PEMParser pemParser = new PEMParser(reader)) {
            Object pemObj = pemParser.readObject();
            if (pemObj instanceof X509Certificate) {
                return (X509Certificate) pemObj;
            } else if (pemObj instanceof X509CertificateHolder) {
                try {
                    return new JcaX509CertificateConverter()
                            .setProvider(BC_PROVIDER)
                            .getCertificate((X509CertificateHolder) pemObj);
                } catch (CertificateException ex) {
                    LOG.error("loadX509Certificate: Caught CertificateException, unable to parse X509 certificate: {}", ex.getMessage());
                    throw new CryptoException(ex);
                }
            }
        } catch (IOException ex) {
            LOG.error("loadX509Certificate: Caught IOException, unable to parse X509 certificate: {}", ex.getMessage());
            throw new CryptoException(ex);
        }
        return null;
    }

    public static PublicKey loadPublicKey(String pemEncoded) throws CryptoException {
        return Crypto.loadPublicKey(new StringReader(pemEncoded));
    }

    public static PublicKey loadPublicKey(Reader r) throws CryptoException {
        try (org.bouncycastle.openssl.PEMParser pemReader = new org.bouncycastle.openssl.PEMParser(r)) {
            Object pemObj = pemReader.readObject();
            JcaPEMKeyConverter pemConverter = new JcaPEMKeyConverter();
            X9ECParameters ecParam = null;

            if (pemObj instanceof ASN1ObjectIdentifier) {

                // make sure this is EC Parameter we're handling. In which case
                // we'll store it and read the next object which should be our
                // EC Public Key

                ASN1ObjectIdentifier ecOID = (ASN1ObjectIdentifier) pemObj;
                ecParam = ECNamedCurveTable.getByOID(ecOID);
                if (ecParam == null) {
                    throw new PEMException("Unable to find EC Parameter for the given curve oid: "
                            + ((ASN1ObjectIdentifier) pemObj).getId());
                }
                pemObj = pemReader.readObject();
            } else if (pemObj instanceof X9ECParameters) {
                ecParam = (X9ECParameters) pemObj;
                pemObj = pemReader.readObject();
            }

            SubjectPublicKeyInfo keyInfo;
            if (pemObj instanceof org.bouncycastle.cert.X509CertificateHolder) {
                keyInfo = ((org.bouncycastle.cert.X509CertificateHolder) pemObj).getSubjectPublicKeyInfo();
            } else {
                keyInfo = (SubjectPublicKeyInfo) pemObj;
            }
            PublicKey pubKey = pemConverter.getPublicKey(keyInfo);

            if (ecParam != null && ECDSA.equals(pubKey.getAlgorithm())) {
                ECParameterSpec ecSpec = new ECParameterSpec(ecParam.getCurve(), ecParam.getG(),
                        ecParam.getN(), ecParam.getH(), ecParam.getSeed());
                KeyFactory keyFactory = KeyFactory.getInstance(getECDSAAlgo(), getKeyFactoryProvider());
                ECPublicKeySpec keySpec = new ECPublicKeySpec(((BCECPublicKey) pubKey).getQ(), ecSpec);
                pubKey = keyFactory.generatePublic(keySpec);
            }
            return pubKey;
        } catch (NoSuchProviderException e) {
            LOG.error("loadPublicKey: Caught NoSuchProviderException, check to make sure the provider is loaded correctly.");
            throw new CryptoException(e);
        } catch (NoSuchAlgorithmException e) {
            LOG.error("loadPublicKey: Caught NoSuchAlgorithmException, check to make sure the algorithm is supported by the provider.");
            throw new CryptoException(e);
        } catch (InvalidKeySpecException e) {
            LOG.error("loadPublicKey: Caught InvalidKeySpecException, invalid key spec is being used.");
            throw new CryptoException("InvalidKeySpecException");
        } catch (IOException e) {
            throw new CryptoException(e);
        }
    }

    public static PublicKey loadPublicKey(File f) throws CryptoException  {
        try (FileReader fileReader = new FileReader(f)) {
            return loadPublicKey(fileReader);
        } catch (FileNotFoundException e) {
            LOG.error("loadPublicKey: Caught FileNotFoundException while attempting to load public key for file: "
                    + f.getAbsolutePath());
            throw new CryptoException(e);
        } catch (IOException e) {
            LOG.error("loadPublicKey: Caught IOException while attempting to load public key for file: "
                    + f.getAbsolutePath());
            throw new CryptoException(e);
        }
    }

    public static PublicKey extractPublicKey(PrivateKey privateKey) throws CryptoException {

        // we only support RSA and ECDSA private keys

        PublicKey publicKey;
        switch (privateKey.getAlgorithm()) {
            case RSA:
                try {
                    KeyFactory kf = KeyFactory.getInstance(getRSAAlgo(), getKeyFactoryProvider());
                    RSAPrivateCrtKey rsaCrtKey = (RSAPrivateCrtKey) privateKey;
                    RSAPublicKeySpec keySpec = new RSAPublicKeySpec(rsaCrtKey.getModulus(),
                            rsaCrtKey.getPublicExponent());
                    publicKey = kf.generatePublic(keySpec);
                } catch (NoSuchProviderException ex) {
                    LOG.error("extractPublicKey: RSA - Caught NoSuchProviderException exception: {}", ex.getMessage());
                    throw new CryptoException(ex);
                } catch (NoSuchAlgorithmException ex) {
                    LOG.error("extractPublicKey: RSA - Caught NoSuchAlgorithmException exception: {}", ex.getMessage());
                    throw new CryptoException(ex);
                } catch (InvalidKeySpecException ex) {
                    LOG.error("extractPublicKey: RSA - Caught InvalidKeySpecException exception: {}", ex.getMessage());
                    throw new CryptoException(ex);
                }
                break;

            case ECDSA:
                try {
                    KeyFactory kf = KeyFactory.getInstance(getECDSAAlgo(), getKeyFactoryProvider());
                    BCECPrivateKey ecPrivKey = (BCECPrivateKey) privateKey;
                    ECMultiplier ecMultiplier = new FixedPointCombMultiplier();
                    ECParameterSpec ecParamSpec = ecPrivKey.getParameters();
                    ECPoint ecPointQ = ecMultiplier.multiply(ecParamSpec.getG(), ecPrivKey.getD());
                    ECPublicKeySpec keySpec = new ECPublicKeySpec(ecPointQ, ecParamSpec);
                    publicKey = kf.generatePublic(keySpec);
                } catch (NoSuchProviderException ex) {
                    LOG.error("extractPublicKey: ECDSA - Caught NoSuchProviderException exception: {}", ex.getMessage());
                    throw new CryptoException(ex);
                } catch (NoSuchAlgorithmException ex) {
                    LOG.error("extractPublicKey: ECDSA - Caught NoSuchAlgorithmException exception: {}", ex.getMessage());
                    throw new CryptoException(ex);
                } catch (InvalidKeySpecException ex) {
                    LOG.error("extractPublicKey: ECDSA - Caught InvalidKeySpecException exception: {}", ex.getMessage());
                    throw new CryptoException(ex);
                }
                break;

            default:
                String msg = "Unsupported Key Algorithm: " + privateKey.getAlgorithm();
                LOG.error("extractPublicKey: {}", msg);
                throw new CryptoException(msg);
        }
        return publicKey;
    }

    public static PrivateKey loadPrivateKey(String pemEncoded) throws CryptoException {
        return Crypto.loadPrivateKey(new StringReader(pemEncoded), null);
    }

    public static PrivateKey loadPrivateKey(Reader reader) throws CryptoException {
        return Crypto.loadPrivateKey(reader, null);
    }

    public static PrivateKey loadPrivateKey(File file) throws CryptoException  {
        return Crypto.loadPrivateKey(file, null);
    }

    public static PrivateKey loadPrivateKey(File file, String pwd) throws CryptoException  {
        try (java.io.FileReader fileReader = new java.io.FileReader(file)) {
            return loadPrivateKey(fileReader, pwd);
        } catch (FileNotFoundException e) {
            LOG.error("loadPrivateKey: Caught FileNotFoundException while attempting to load private key for file: "
                    + file.getAbsolutePath());
            throw new CryptoException(e);
        } catch (IOException e) {
            LOG.error("loadPrivateKey: Caught IOException while attempting to load private key for file: "
                    + file.getAbsolutePath());
            throw new CryptoException(e);
        }
    }

    public static PrivateKey loadPrivateKey(String pemEncoded, String pwd) throws CryptoException {
        return Crypto.loadPrivateKey(new StringReader(pemEncoded), pwd);
    }

    public static PrivateKey loadPrivateKey(Reader reader, String pwd) throws CryptoException {

        try (PEMParser pemReader = new PEMParser(reader)) {
            PrivateKey privKey = null;
            X9ECParameters ecParam = null;

            Object pemObj = pemReader.readObject();

            if (pemObj instanceof ASN1ObjectIdentifier) {

                // make sure this is EC Parameter we're handling. In which case
                // we'll store it and read the next object which should be our
                // EC Private Key

                ASN1ObjectIdentifier ecOID = (ASN1ObjectIdentifier) pemObj;
                ecParam = ECNamedCurveTable.getByOID(ecOID);
                if (ecParam == null) {
                    throw new PEMException("Unable to find EC Parameter for the given curve oid: "
                            + ((ASN1ObjectIdentifier) pemObj).getId());
                }

                pemObj = pemReader.readObject();

            } else if (pemObj instanceof X9ECParameters) {

                ecParam = (X9ECParameters) pemObj;
                pemObj = pemReader.readObject();
            }

            if (pemObj instanceof PEMKeyPair) {

                PrivateKeyInfo pKeyInfo = ((PEMKeyPair) pemObj).getPrivateKeyInfo();
                JcaPEMKeyConverter pemConverter = new JcaPEMKeyConverter();
                privKey = pemConverter.getPrivateKey(pKeyInfo);
            } else if (pemObj instanceof PKCS8EncryptedPrivateKeyInfo) {
                PKCS8EncryptedPrivateKeyInfo pKeyInfo = (PKCS8EncryptedPrivateKeyInfo) pemObj;
                if (pwd == null) {
                    throw new CryptoException("No password specified to decrypt encrypted private key");
                }

                // Decrypt the private key with the specified password

                InputDecryptorProvider pkcs8Prov = new JceOpenSSLPKCS8DecryptorProviderBuilder()
                        .setProvider(BC_PROVIDER).build(pwd.toCharArray());

                PrivateKeyInfo privateKeyInfo = pKeyInfo.decryptPrivateKeyInfo(pkcs8Prov);
                JcaPEMKeyConverter pemConverter = new JcaPEMKeyConverter();
                privKey = pemConverter.getPrivateKey(privateKeyInfo);
            } else if (pemObj instanceof PrivateKeyInfo) {

                PrivateKeyInfo pKeyInfo = (PrivateKeyInfo) pemObj;
                JcaPEMKeyConverter pemConverter = new JcaPEMKeyConverter();
                privKey = pemConverter.getPrivateKey(pKeyInfo);
            }

            // if our private key is EC type and we have parameters specified
            // then we need to set it accordingly

            if (ecParam != null && privKey != null && ECDSA.equals(privKey.getAlgorithm())) {
                ECParameterSpec ecSpec = new ECParameterSpec(ecParam.getCurve(), ecParam.getG(),
                        ecParam.getN(), ecParam.getH(), ecParam.getSeed());
                KeyFactory keyFactory = KeyFactory.getInstance(getECDSAAlgo(), getKeyFactoryProvider());
                ECPrivateKeySpec keySpec = new ECPrivateKeySpec(((BCECPrivateKey) privKey).getS(), ecSpec);
                privKey = keyFactory.generatePrivate(keySpec);
            }

            return privKey;
        } catch (PEMException e) {
            LOG.error("loadPrivateKey: Caught PEMException, problem with format of key detected.");
            throw new CryptoException(e);
        } catch (NoSuchProviderException e) {
            LOG.error("loadPrivateKey: Caught NoSuchProviderException, check to make sure the provider is loaded correctly.");
            throw new CryptoException(e);
        } catch (NoSuchAlgorithmException e) {
            LOG.error("loadPrivateKey: Caught NoSuchAlgorithmException, check to make sure the algorithm is supported by the provider.");
            throw new CryptoException(e);
        } catch (InvalidKeySpecException e) {
            LOG.error("loadPrivateKey: Caught InvalidKeySpecException, invalid key spec is being used.");
            throw new CryptoException(e);
        } catch (OperatorCreationException e) {
            LOG.error("loadPrivateKey: Caught OperatorCreationException when creating JceOpenSSLPKCS8DecryptorProviderBuilder.");
            throw new CryptoException(e);
        } catch (PKCSException e) {
            LOG.error("loadPrivateKey: Caught PKCSException when decrypting private key.");
            throw new CryptoException(e);
        } catch (IOException e) {
            LOG.error("loadPrivateKey: Caught IOException, while trying to read key.");
            throw new CryptoException(e);
        }
    }

    /**
     * Generate a RSA private with the given number of bits
     * @param bits numbers of bits
     * @return PrivateKey private key
     * @throws CryptoException for any failures
     */
    public static PrivateKey generateRSAPrivateKey(int bits) throws CryptoException {
        KeyPairGenerator keyGen;
        try {
            keyGen = KeyPairGenerator.getInstance(RSA);
        } catch (NoSuchAlgorithmException e) {
            LOG.error("generatePrivateKey: Caught NoSuchAlgorithmException, check to make sure the algorithm is supported by the provider.");
            throw new CryptoException(e);
        }
        keyGen.initialize(bits);
        return keyGen.genKeyPair().getPrivate();
    }

    public static String randomSalt() {
        long v = RANDOM.nextLong();
        return Long.toHexString(v);
    }

    public static String encodedFile(File f) {
        try (FileInputStream in = new FileInputStream(f)) {
            int fileLength = (int) f.length();
            byte [] buf = new byte[fileLength];
            if (in.read(buf) != fileLength) {
                LOG.error("encodedFile: Unable to read {} bytes from file {}", fileLength, f.getAbsolutePath());
                throw new IOException("Unable to read file");
            }
            return ybase64(buf);
        } catch (FileNotFoundException e) {
            LOG.error("encodedFile: Caught FileNotFoundException while attempting to read encoded file: "
                    + f.getAbsolutePath());
            throw new RuntimeException(e);
        } catch (IOException e) {
            LOG.error("encodedFile: Caught IOException while attempting to read encoded file: "
                    + f.getAbsolutePath());
            throw new RuntimeException(e);
        }
    }

    public static String encodedFile(FileInputStream is) {
        try {
            byte [] buf = new byte[4096];
            int readBytes;
            String contents = null;
            while ((readBytes = is.read(buf)) > 0) {
                if (contents == null) {
                    contents = new String(buf, 0, readBytes - 1);
                } else {
                    contents = contents.concat(new String(buf, 0, readBytes - 1));
                }
            }
            if (contents == null) {
                throw new IOException("Unable to read any data from file stream");
            }
            return ybase64(utf8Bytes(contents));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static PKCS10CertificationRequest getPKCS10CertRequest(String csr) {

        if (csr == null || csr.isEmpty()) {
            LOG.error("getPKCS10CertRequest: CSR is null or empty");
            throw new CryptoException("CSR is null or empty");
        }

        try {
            Reader csrReader = new StringReader(csr);
            try (PEMParser pemParser = new PEMParser(csrReader)) {
                Object pemObj = pemParser.readObject();
                if (pemObj instanceof PKCS10CertificationRequest) {
                    return (PKCS10CertificationRequest) pemObj;
                }
            }
        } catch (IOException ex) {
            LOG.error("getPKCS10CertRequest: unable to parse csr: {}", ex.getMessage());
            throw new CryptoException(ex);
        }
        return null;
    }

    public static String extractX509CSRSubjectField(PKCS10CertificationRequest certReq, ASN1ObjectIdentifier id) {

        X500Name x500name = certReq.getSubject();
        if (x500name == null) {
            return null;
        }
        RDN[] rdns = x500name.getRDNs(id);

        // we're only supporting a single field in Athenz certificates so
        // any other multiple value will be considered invalid

        if (rdns == null || rdns.length == 0) {
            return null;
        }

        if (rdns.length != 1) {
            throw new CryptoException("CSR Subject contains multiple values for the same field.");
        }

        return IETFUtils.valueToString(rdns[0].getFirst().getValue());
    }

    public static String extractX509CSRCommonName(PKCS10CertificationRequest certReq) {
        // in case there are multiple CNs, we're only looking at the first one
        // in Athenz we should never have multiple CNs so we're going to reject
        // any csr that has multiple values

        return extractX509CSRSubjectField(certReq, BCStyle.CN);
    }

    public static String extractX509CSRSubjectOField(PKCS10CertificationRequest certReq) {

        // in case there are multiple Os, we're only looking at the first one
        // in Athenz we should never have multiple Os so we're going to reject
        // any csr that has multiple values

        return extractX509CSRSubjectField(certReq, BCStyle.O);
    }

    public static String extractX509CSRSubjectOUField(PKCS10CertificationRequest certReq) {

        // in case there are multiple OUs, we're only looking at the first one
        // in Athenz we should never have multiple OUs so we're going to reject
        // any certificate that has multiple values

        return extractX509CSRSubjectField(certReq, BCStyle.OU);
    }

    private static List<String> extractX509CSRSANField(PKCS10CertificationRequest certReq, int tagNo) {

        List<String> values = new ArrayList<>();
        Attribute[] attributes = certReq.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        for (Attribute attribute : attributes) {
            for (ASN1Encodable value : attribute.getAttributeValues()) {
                Extensions extensions = Extensions.getInstance(value);
                GeneralNames gns = GeneralNames.fromExtensions(extensions, Extension.subjectAlternativeName);
                if (gns == null) {
                    continue;
                }
                for (GeneralName name : gns.getNames()) {

                    // GeneralName ::= CHOICE {
                    //     otherName                       [0]     OtherName,
                    //     rfc822Name                      [1]     IA5String,
                    //     dNSName                         [2]     IA5String,
                    //     x400Address                     [3]     ORAddress,
                    //     directoryName                   [4]     Name,
                    //     ediPartyName                    [5]     EDIPartyName,
                    //     uniformResourceIdentifier       [6]     IA5String,
                    //     iPAddress                       [7]     OCTET STRING,
                    //     registeredID                    [8]     OBJECT IDENTIFIER}

                    if (name.getTagNo() == tagNo) {
                        values.add(((DERIA5String) name.getName()).getString());
                    }
                }
            }
        }
        return values;
    }

    public static String extractX509CSREmail(PKCS10CertificationRequest certReq) {
        List<String> emails = extractX509CSRSANField(certReq, GeneralName.rfc822Name);
        if (emails.size() == 0) {
            return null;
        }
        return emails.get(0);
    }

    public static List<String> extractX509CSREmails(PKCS10CertificationRequest certReq) {
        return extractX509CSRSANField(certReq, GeneralName.rfc822Name);
    }

    public static List<String> extractX509CSRDnsNames(PKCS10CertificationRequest certReq) {
        return extractX509CSRSANField(certReq, GeneralName.dNSName);
    }

    public static List<String> extractX509CSRURIs(PKCS10CertificationRequest certReq) {
        return extractX509CSRSANField(certReq, GeneralName.uniformResourceIdentifier);
    }

    public static List<String> extractX509CSRIPAddresses(PKCS10CertificationRequest certReq) {

        List<String> ipAddresses = new ArrayList<>();
        Attribute[] attributes = certReq.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        for (Attribute attribute : attributes) {
            for (ASN1Encodable value : attribute.getAttributeValues()) {
                Extensions extensions = Extensions.getInstance(value);
                GeneralNames gns = GeneralNames.fromExtensions(extensions, Extension.subjectAlternativeName);
                if (gns == null) {
                    continue;
                }
                for (GeneralName name : gns.getNames()) {
                    if (name.getTagNo() == GeneralName.iPAddress) {
                        try {
                            InetAddress addr = InetAddress.getByAddress(((DEROctetString) name.getName()).getOctets());
                            ipAddresses.add(addr.getHostAddress());
                        } catch (UnknownHostException ignored) {
                        }
                    }
                }
            }
        }
        return ipAddresses;
    }

    public static String extractX509CSRPublicKey(PKCS10CertificationRequest certReq) {

        JcaPEMKeyConverter pemConverter = new JcaPEMKeyConverter();
        PublicKey publicKey;
        try {
            publicKey = pemConverter.getPublicKey(certReq.getSubjectPublicKeyInfo());
        } catch (PEMException ex) {
            LOG.error("extractX509CSRPublicKey: unable to get public key: {}", ex.getMessage());
            return null;
        }
        return convertToPEMFormat(publicKey);
    }

    public static String generateX509CSR(PrivateKey privateKey, String x500Principal, GeneralName[] sanArray)
            throws OperatorCreationException, IOException, NoSuchAlgorithmException {
        final PublicKey publicKey = extractPublicKey(privateKey);
        if (publicKey == null) {
            throw new CryptoException("Unable to extract public key from private key");
        }
        return generateX509CSR(privateKey, publicKey, x500Principal, sanArray);
    }

    public static String generateX509CSR(PrivateKey privateKey, PublicKey publicKey, String x500Principal,
            GeneralName[] sanArray) throws OperatorCreationException, IOException, NoSuchAlgorithmException {

        // Create Distinguished Name

        X500Principal subject = new X500Principal(x500Principal);

        // Create ContentSigner

        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(
                getSignatureAlgorithm(privateKey.getAlgorithm(), SHA256));
        ContentSigner signer = csBuilder.build(privateKey);

        // Create the CSR

        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                subject, publicKey);

        // Add SubjectAlternativeNames (SAN) if specified
        if (sanArray != null) {
            ExtensionsGenerator extGen = new ExtensionsGenerator();
            GeneralNames subjectAltNames = new GeneralNames(sanArray);
            extGen.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);
            p10Builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
        }

        PKCS10CertificationRequest csr = p10Builder.build(signer);

        // write to openssl PEM format

        PemObject pemObject = new PemObject("CERTIFICATE REQUEST", csr.getEncoded());
        StringWriter strWriter;
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(strWriter = new StringWriter())) {
            pemWriter.writeObject(pemObject);
        }
        return strWriter.toString();
    }

    /**
     * extractX500DnField extracts a sub part from the DN
     * @param principalName a string representing the DN
     * @param id ASN1ObjectIdentifier for the sub part
     * @return string with the subpart of the DN
     */
    public static String extractX500DnField(String principalName, ASN1ObjectIdentifier id) {
        if (principalName == null || principalName.isEmpty()) {
            return null;
        }
        X500Name x500name = new X500Name(principalName);
        RDN[] rdns = x500name.getRDNs(id);

        // we're only supporting a single field in Athenz certificates so
        // any other multiple value will be considered invalid

        if (rdns == null || rdns.length == 0) {
            return null;
        }
        if (rdns.length != 1) {
            throw new CryptoException("CSR Subject contains multiple values for the same field.");
        }
        return IETFUtils.valueToString(rdns[0].getFirst().getValue());
    }

    /**
     * extractX509CertSubjectField returns the sub part from the Subject DN
     * @param x509Cert X509Certificate to extract the Subject Field from
     * @param id ASN1ObjectIdentifier for the sub part
     * @return string representing Subject field requested
     */
    public static String extractX509CertSubjectField(X509Certificate x509Cert, ASN1ObjectIdentifier id) {
        return extractX500DnField(x509Cert.getSubjectX500Principal().getName(), id);
    }

    /**
     * extractX509CertIssuerDnField returns the sub part from the Issuer DN
     * @param x509Cert X509Certificate to extract the Issuer DN Field from
     * @param id ASN1ObjectIdentifier for the sub part
     * @return string representing Issuer DN field requested
     */
    public static String extractX509CertIssuerDnField(X509Certificate x509Cert, ASN1ObjectIdentifier id) {
        return extractX500DnField(x509Cert.getIssuerX500Principal().getName(), id);
    }

    /**
     * extractX509CertIssuerCommonName returns the CN from the Issuer DN
     * @param x509Cert X509Certificate to extract the Issuer CN from
     * @return string representing the Issuer CN
     */
    public static String extractX509CertIssuerCommonName(X509Certificate x509Cert) {
        return extractX509CertIssuerDnField(x509Cert, BCStyle.CN);
    }

    public static long extractX509CertIssueTime(X509Certificate x509Cert) {
        return x509Cert.getNotBefore().getTime() / 1000;
    }
    public static String extractX509CertCommonName(X509Certificate x509Cert) {

        // in case there are multiple CNs, we're only looking at the first one
        // in Athenz we should never have multiple CNs so we're going to reject
        // any certificate that has multiple values

        return extractX509CertSubjectField(x509Cert, BCStyle.CN);
    }

    public static String extractX509CertSubjectOUField(X509Certificate x509Cert) {

        // in case there are multiple OUs, we're only looking at the first one
        // in Athenz we should never have multiple OUs so we're going to reject
        // any certificate that has multiple values

        return extractX509CertSubjectField(x509Cert, BCStyle.OU);
    }

    public static String extractX509CertSubjectOField(X509Certificate x509Cert) {

        // in case there are multiple Os, we're only looking at the first one
        // in Athenz we should never have multiple Os so we're going to reject
        // any certificate that has multiple values

        return extractX509CertSubjectField(x509Cert, BCStyle.O);
    }

    public static boolean isRestrictedCertificate(X509Certificate x509Cert, GlobStringsMatcher globStringsMatcher) {

        if (x509Cert == null) {
            LOG.debug("isRestrictedCertificate: Required argument x509Cert is null. Returning true.");
            return true;
        }

        final String x509Ou = extractX509CertSubjectOUField(x509Cert);
        if (x509Ou == null || x509Ou.isEmpty()) {
            // certificate has no ou field
            return false;
        }

        // if it ends with our configured restricted suffix
        // then there is no need to check for the regex match

        if (x509Ou.endsWith(CERT_RESTRICTED_SUFFIX)) {
            return true;
        }

        if (globStringsMatcher == null) {
            LOG.debug("isRestrictedCertificate: Required argument globStringsMatcher is null. Returning true.");
            return true;
        }
        if (globStringsMatcher.isEmptyPatternsList()) {
            // No patterns provided, no need to check for mTLS restriction
            return false;
        }
        return globStringsMatcher.isMatch(x509Ou);
    }

    private static List<String> extractX509CertSANField(X509Certificate x509Cert, int tagNo) {
        Collection<List<?>> altNames = null;
        try {
            altNames = x509Cert.getSubjectAlternativeNames();
        } catch (CertificateParsingException ex) {
            LOG.error("extractX509IPAddresses: Caught CertificateParsingException when parsing certificate: "
                    + ex.getMessage());
        }
        if (altNames == null) {
            return Collections.emptyList();
        }

        List<String> values = new ArrayList<>();
        for (@SuppressWarnings("rawtypes") List item : altNames) {
            Integer type = (Integer) item.get(0);

            // GeneralName ::= CHOICE {
            //     otherName                       [0]     OtherName,
            //     rfc822Name                      [1]     IA5String,
            //     dNSName                         [2]     IA5String,
            //     x400Address                     [3]     ORAddress,
            //     directoryName                   [4]     Name,
            //     ediPartyName                    [5]     EDIPartyName,
            //     uniformResourceIdentifier       [6]     IA5String,
            //     iPAddress                       [7]     OCTET STRING,
            //     registeredID                    [8]     OBJECT IDENTIFIER}

            if (type == tagNo) {
                values.add((String) item.get(1));
            }
        }
        return values;
    }

    public static List<String> extractX509CertDnsNames(X509Certificate x509Cert) {
        return extractX509CertSANField(x509Cert, GeneralName.dNSName);
    }

    public static List<String> extractX509CertEmails(X509Certificate x509Cert) {
        return extractX509CertSANField(x509Cert, GeneralName.rfc822Name);
    }

    public static List<String> extractX509CertIPAddresses(X509Certificate x509Cert) {
        return extractX509CertSANField(x509Cert, GeneralName.iPAddress);
    }

    public static List<String> extractX509CertURIs(X509Certificate x509Cert) {
        return extractX509CertSANField(x509Cert, GeneralName.uniformResourceIdentifier);
    }

    public static String extractX509CertSpiffeUri(X509Certificate x509Cert) {
        // each certificate must have a single SPIFFE URI
        // if there are multiple we'll reject and return null
        List<String> uris = extractX509CertURIs(x509Cert);
        String spiffeUri = null;
        for (String uri : uris) {
            if (!uri.toLowerCase().startsWith(CERT_SPIFFE_URI)) {
                continue;
            }
            if (spiffeUri != null) {
                return null;
            }
            spiffeUri = uri;
        }
        return spiffeUri;
    }

    public static String extractX509CertPublicKey(X509Certificate x509Cert) {

        PublicKey publicKey = x509Cert.getPublicKey();
        if (publicKey == null) {
            LOG.error("extractX509CertPublicKey: unable to get public key");
            return null;
        }
        return convertToPEMFormat(publicKey);
    }

    public static X500Name utf8DEREncodedIssuer(final String issuer) {

        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        X500Name x500Name = new X500Name(issuer);
        RDN[] rdns = x500Name.getRDNs();

        // for compatibility with openssl generated certificates
        // we're going to make sure all the RDNs in the issuer
        // field are encoded as UTF8Strings except for C field
        // which is encoded as a PrintableString

        for (int i = rdns.length - 1; i >= 0; i--) {
            ASN1ObjectIdentifier asn1ObjectIdentifier = rdns[i].getFirst().getType();
            ASN1Encodable value = (asn1ObjectIdentifier == BCStyle.C) ?
                new DERPrintableString(IETFUtils.valueToString(rdns[i].getFirst().getValue())) :
                new DERUTF8String(IETFUtils.valueToString(rdns[i].getFirst().getValue()));
            builder.addRDN(asn1ObjectIdentifier, value);
        }
        return builder.build();
    }

    public static X509Certificate generateX509Certificate(PKCS10CertificationRequest certReq,
            PrivateKey caPrivateKey, X509Certificate caCertificate, int validityTimeout,
            boolean basicConstraints) {

        X500Name issuer = utf8DEREncodedIssuer(caCertificate.getSubjectX500Principal().getName());
        return generateX509Certificate(certReq, caPrivateKey, issuer, validityTimeout, basicConstraints);
    }

    public static X509Certificate generateX509Certificate(PKCS10CertificationRequest certReq,
            PrivateKey caPrivateKey, X500Name issuer, int validityTimeout,
            boolean basicConstraints) {

        // set validity for the given number of minutes from now

        Date notBefore = new Date();
        Calendar cal = Calendar.getInstance();
        cal.setTime(notBefore);
        cal.add(Calendar.MINUTE, validityTimeout);
        Date notAfter = cal.getTime();

        // Generate self-signed certificate

        X509Certificate cert;
        try {
            JcaPKCS10CertificationRequest jcaPKCS10CertificationRequest = new JcaPKCS10CertificationRequest(certReq);
            PublicKey publicKey = jcaPKCS10CertificationRequest.getPublicKey();

            SecureRandom random = new SecureRandom();
            BigInteger serial = new BigInteger(160, random);

            X509v3CertificateBuilder caBuilder = new JcaX509v3CertificateBuilder(issuer, serial,
                        notBefore, notAfter, certReq.getSubject(), publicKey)
                    .addExtension(Extension.basicConstraints, basicConstraints,
                            new BasicConstraints(basicConstraints))
                    .addExtension(Extension.extendedKeyUsage, false,
                            new ExtendedKeyUsage(new KeyPurposeId[]
                                    { KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth }));

            if (basicConstraints) {
                caBuilder = caBuilder.addExtension(Extension.keyUsage, false,
                        new X509KeyUsage(X509KeyUsage.digitalSignature | X509KeyUsage.keyEncipherment |
                                X509KeyUsage.keyCertSign | X509KeyUsage.cRLSign));
            } else {
                final PublicKey caPublicKey = extractPublicKey(caPrivateKey);
                caBuilder = caBuilder.addExtension(Extension.keyUsage, false,
                            new X509KeyUsage(X509KeyUsage.digitalSignature | X509KeyUsage.keyEncipherment))
                        .addExtension(Extension.authorityKeyIdentifier, false,
                            new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(caPublicKey));
            }

            // see if we have the dns/rfc822/ip address extensions specified in the csr

            ArrayList<GeneralName> altNames = new ArrayList<>();
            Attribute[] certAttributes = jcaPKCS10CertificationRequest.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
            if (certAttributes != null && certAttributes.length > 0) {
                for (Attribute attribute : certAttributes) {
                    Extensions extensions = Extensions.getInstance(attribute.getAttrValues().getObjectAt(0));
                    GeneralNames gns = GeneralNames.fromExtensions(extensions, Extension.subjectAlternativeName);
                    if (gns == null) {
                        continue;
                    }
                    GeneralName[] names = gns.getNames();
                    for (GeneralName name : names) {
                        switch (name.getTagNo()) {
                            case GeneralName.dNSName:
                            case GeneralName.iPAddress:
                            case GeneralName.rfc822Name:
                            case GeneralName.uniformResourceIdentifier:
                                altNames.add(name);
                                break;
                        }
                    }
                }
                if (!altNames.isEmpty()) {
                    caBuilder.addExtension(Extension.subjectAlternativeName, false,
                            new GeneralNames(altNames.toArray(new GeneralName[0])));
                }
            }

            String signatureAlgorithm = getSignatureAlgorithm(caPrivateKey.getAlgorithm(), SHA256);
            ContentSigner caSigner = new JcaContentSignerBuilder(signatureAlgorithm)
                    .setProvider(BC_PROVIDER).build(caPrivateKey);

            JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider(BC_PROVIDER);
            cert = converter.getCertificate(caBuilder.build(caSigner));
        } catch (CertificateException ex) {
            LOG.error("generateX509Certificate: Caught CertificateException when generating certificate", ex);
            throw new CryptoException(ex);
        } catch (OperatorCreationException ex) {
            LOG.error("generateX509Certificate: Caught OperatorCreationException when creating JcaContentSignerBuilder", ex);
            throw new CryptoException(ex);
        } catch (InvalidKeyException ex) {
            LOG.error("generateX509Certificate: Caught InvalidKeySpecException, invalid key spec is being used", ex);
            throw new CryptoException(ex);
        } catch (NoSuchAlgorithmException ex) {
            LOG.error("generateX509Certificate: Caught NoSuchAlgorithmException, check to make sure the algorithm is supported by the provider", ex) ;
            throw new CryptoException(ex);
        } catch (Exception ex) {
            LOG.error("generateX509Certificate: unable to generate X509 Certificate", ex);
            throw new CryptoException("Unable to generate X509 Certificate");
        }
        return cert;
    }
    public static boolean validatePKCS7Signature(String data, String signature, PublicKey publicKey) {

        try {
            SignerInformationStore signerStore;
            try (InputStream sigIs = new ByteArrayInputStream(Base64.decode(signature.getBytes(StandardCharsets.UTF_8)))) {
                CMSProcessable content = new CMSProcessableByteArray(data.getBytes(StandardCharsets.UTF_8));
                CMSSignedData signedData = new CMSSignedData(content, sigIs);
                signerStore = signedData.getSignerInfos();
            }

            Collection<SignerInformation> signers = signerStore.getSigners();
            Iterator<SignerInformation> it = signers.iterator();

            SignerInformationVerifier infoVerifier = new JcaSimpleSignerInfoVerifierBuilder()
                    .setProvider(BC_PROVIDER).build(publicKey);
            while (it.hasNext()) {
                SignerInformation signerInfo = it.next();
                if (signerInfo.verify(infoVerifier)) {
                    return true;
                }
            }
        } catch (CMSException ex) {
            LOG.error("validatePKCS7Signature: unable to initialize CMSSignedData object: {}", ex.getMessage());
            throw new CryptoException(ex);
        } catch (OperatorCreationException ex) {
            LOG.error("validatePKCS7Signature: Caught OperatorCreationException when creating JcaSimpleSignerInfoVerifierBuilder: {}",
                    ex.getMessage());
            throw new CryptoException(ex);
        } catch (IOException ex) {
            LOG.error("validatePKCS7Signature: Caught IOException when closing InputStream: {}", ex.getMessage());
            throw new CryptoException(ex);
        } catch (Exception ex) {
            LOG.error("validatePKCS7Signature: unable to validate signature: {}", ex.getMessage());
            throw new CryptoException(ex.getMessage());
        }

        return false;
    }
    public static String convertToPEMFormat(Object obj) {
        StringWriter writer = new StringWriter();
        try {
            try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
                pemWriter.writeObject(obj);
                pemWriter.flush();
            }
        } catch (IOException ex) {
            LOG.error("convertToPEMFormat: unable to convert object to PEM: {}", ex.getMessage());
            return null;
        }
        return writer.toString();
    }

    public static Map<String, String> parseJWSProtectedHeader(final String protectedHeader) {

        java.util.Base64.Decoder base64Decoder = java.util.Base64.getUrlDecoder();
        try {
            byte[] protectedHeaderBytes = base64Decoder.decode(protectedHeader);
            return JSON_MAPPER.readValue(protectedHeaderBytes, Map.class);
        } catch (Exception ex) {
            LOG.error("Unable to parse jws domain protected header", ex);
        }
        return null;
    }

    public static boolean validateJWSDocument(final String protectedHeader, final String payload,
            final String signature, Function<String, PublicKey> publicKeyGetter) {

        final Map<String, String> jwsHeader = parseJWSProtectedHeader(protectedHeader);
        if (jwsHeader == null) {
            LOG.error("Unable to parse JWS header field");
            return false;
        }

        final String keyId = jwsHeader.get("kid");
        if (keyId == null) {
            LOG.error("missing jws kid header");
            return false;
        }

        PublicKey publicKey = publicKeyGetter.apply(keyId);
        if (publicKey == null) {
            LOG.error("public Key id={} not available", keyId);
            return false;
        }

        boolean result = false;
        java.util.Base64.Decoder base64Decoder = java.util.Base64.getUrlDecoder();

        try {
            byte[] signatureBytes = base64Decoder.decode(signature);
            final String signedData = protectedHeader + "." + payload;
            result = Crypto.verify(signedData.getBytes(StandardCharsets.UTF_8),
                    publicKey, signatureBytes, getDigestAlgorithm(jwsHeader.get("alg")));
        } catch (Exception ex) {
            LOG.error("signature validation exception", ex);
        }

        return result;
    }

    /**
     *
     * @param x509Certificate object to extract Issuer DN from
     * @return extracted Issuer DN
     */
    public static String extractIssuerDn(X509Certificate x509Certificate) {
        return x509Certificate.getIssuerX500Principal().getName();
    }

    /**
     *
     * @param certificateBundlePath trust store pem file path
     * @return Set of extracted Issuer Dns
     */
    public static Set<String> extractIssuerDn(String certificateBundlePath) {
        if (certificateBundlePath == null || certificateBundlePath.isEmpty()) {
            return new HashSet<>();
        }
        Set<String> issuerDN = new HashSet<>();
        X509Certificate[] certificates = loadX509Certificates(certificateBundlePath);
        for (X509Certificate cert: certificates) {
            issuerDN.add(extractIssuerDn(cert));
        }
        return issuerDN;
    }
}
