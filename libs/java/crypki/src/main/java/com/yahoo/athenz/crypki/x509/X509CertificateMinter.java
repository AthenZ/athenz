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
package com.yahoo.athenz.crypki.x509;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.crypki.CrypkiException;
import com.yahoo.athenz.crypki.X509SignRequest;
import com.yahoo.athenz.crypki.signer.SigningKey;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Shared leaf-cert template: CSR subject/SAN, EKU, validity cap, 1-hour backdate.
 */
public class X509CertificateMinter {

    public static final int EKU_SERVER_AUTH = 1;
    public static final int EKU_CLIENT_AUTH = 2;
    public static final int EKU_CODE_SIGNING = 3;
    public static final int EKU_TIME_STAMPING = 8;
    private static final int BACKDATE_SECONDS = 3600;

    private final int maxValiditySeconds;

    public X509CertificateMinter(int maxValiditySeconds) {
        this.maxValiditySeconds = maxValiditySeconds;
    }

    public String sign(SigningKey signingKey, X509SignRequest request) {
        return sign(contentSigner(signingKey.getPrivateKey()), signingKey.getCaCertificate(), request);
    }

    public String sign(ContentSigner contentSigner, X509Certificate caCertificate, X509SignRequest request) {
        return Crypto.convertToPEMFormat(signCertificate(contentSigner, caCertificate, request));
    }

    public X509Certificate signCertificate(PrivateKey privateKey, X509Certificate caCertificate,
            X509SignRequest request) {
        return signCertificate(contentSigner(privateKey), caCertificate, request);
    }

    public X509Certificate signCertificate(ContentSigner contentSigner, X509Certificate caCertificate,
            X509SignRequest request) {
        if (request == null || request.getCsrPem() == null || request.getCsrPem().isEmpty()) {
            throw new CrypkiException("CSR is required");
        }
        PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(request.getCsrPem());
        if (certReq == null) {
            throw new CrypkiException("Unable to parse CSR");
        }
        int validitySeconds = request.getValiditySeconds() > 0
                ? Math.min(request.getValiditySeconds(), maxValiditySeconds) : maxValiditySeconds;
        Instant notAfter = Instant.now();
        Instant notBefore = notAfter.minusSeconds(BACKDATE_SECONDS);
        notAfter = notBefore.plusSeconds(validitySeconds + BACKDATE_SECONDS);
        try {
            JcaPKCS10CertificationRequest jcaReq = new JcaPKCS10CertificationRequest(certReq);
            PublicKey publicKey = jcaReq.getPublicKey();
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    new JcaX509CertificateHolder(caCertificate).getSubject(),
                    new BigInteger(128, new SecureRandom()),
                    Date.from(notBefore),
                    Date.from(notAfter),
                    certReq.getSubject(),
                    publicKey)
                    .addExtension(Extension.basicConstraints, false, new BasicConstraints(false))
                    .addExtension(Extension.keyUsage, true,
                            new X509KeyUsage(X509KeyUsage.digitalSignature | X509KeyUsage.keyEncipherment))
                    .addExtension(Extension.extendedKeyUsage, false, toExtendedKeyUsage(request.getExtKeyUsage()))
                    .addExtension(Extension.authorityKeyIdentifier, false,
                            new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(caCertificate));
            addSubjectAlternativeNames(builder, jcaReq);
            return new JcaX509CertificateConverter().getCertificate(builder.build(contentSigner));
        } catch (CrypkiException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new CrypkiException("Unable to sign X.509 certificate: " + ex.getMessage(), ex);
        }
    }

    static ContentSigner contentSigner(PrivateKey privateKey) {
        String algorithm = "EC".equalsIgnoreCase(privateKey.getAlgorithm())
                ? "SHA256withECDSA" : "SHA256withRSA";
        try {
            return new JcaContentSignerBuilder(algorithm).build(privateKey);
        } catch (Exception first) {
            for (Provider provider : Security.getProviders()) {
                if (provider.getName().startsWith("SunPKCS11")) {
                    try {
                        return new JcaContentSignerBuilder(algorithm).setProvider(provider).build(privateKey);
                    } catch (Exception ignored) {
                        // try the next PKCS#11 provider
                    }
                }
            }
            throw new CrypkiException("Unable to create content signer", first);
        }
    }

    static ExtendedKeyUsage toExtendedKeyUsage(List<Integer> extKeyUsage) {
        List<Integer> values = (extKeyUsage == null || extKeyUsage.isEmpty())
                ? List.of(EKU_SERVER_AUTH, EKU_CLIENT_AUTH) : extKeyUsage;
        KeyPurposeId[] purposes = new KeyPurposeId[values.size()];
        for (int i = 0; i < values.size(); i++) {
            purposes[i] = toKeyPurposeId(values.get(i));
        }
        return new ExtendedKeyUsage(purposes);
    }

    static KeyPurposeId toKeyPurposeId(int eku) {
        switch (eku) {
            case EKU_SERVER_AUTH:
                return KeyPurposeId.id_kp_serverAuth;
            case EKU_CLIENT_AUTH:
                return KeyPurposeId.id_kp_clientAuth;
            case EKU_CODE_SIGNING:
                return KeyPurposeId.id_kp_codeSigning;
            case EKU_TIME_STAMPING:
                return KeyPurposeId.id_kp_timeStamping;
            default:
                return KeyPurposeId.id_kp_clientAuth;
        }
    }

    private static void addSubjectAlternativeNames(X509v3CertificateBuilder builder,
            JcaPKCS10CertificationRequest jcaReq) throws Exception {
        ArrayList<GeneralName> altNames = new ArrayList<>();
        Attribute[] attributes = jcaReq.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        if (attributes == null) {
            return;
        }
        for (Attribute attribute : attributes) {
            Extensions extensions = Extensions.getInstance(attribute.getAttrValues().getObjectAt(0));
            GeneralNames gns = GeneralNames.fromExtensions(extensions, Extension.subjectAlternativeName);
            if (gns == null) {
                continue;
            }
            for (GeneralName name : gns.getNames()) {
                switch (name.getTagNo()) {
                    case GeneralName.dNSName:
                    case GeneralName.iPAddress:
                    case GeneralName.rfc822Name:
                    case GeneralName.uniformResourceIdentifier:
                        altNames.add(name);
                        break;
                    default:
                        break;
                }
            }
        }
        if (!altNames.isEmpty()) {
            builder.addExtension(Extension.subjectAlternativeName, false,
                    new GeneralNames(altNames.toArray(new GeneralName[0])));
        }
    }
}
