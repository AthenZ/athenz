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
package io.athenz.server.aws.common.cert.impl;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.crypki.CrypkiConsts;
import com.yahoo.athenz.crypki.CrypkiException;
import com.yahoo.athenz.crypki.hsm.HsmClient;
import com.yahoo.athenz.crypki.signer.SigningKey;
import org.eclipse.jetty.util.StringUtil;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.AuthProvider;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import javax.security.auth.callback.PasswordCallback;

/**
 * CloudHSM {@link HsmClient}: CloudHSM JCE when present, otherwise
 * SunPKCS11. The CA PEM is loaded from disk. The private key never
 * leaves the HSM.
 *
 * <p>SunPKCS11's PKCS#11 {@code KeyStore} only exposes private keys that
 * have a matching certificate object, so CloudHSM JCE
 * ({@code /opt/cloudhsm/java/cloudhsm-jce-*.jar}) is required for a
 * label-only sign key.
 */
public class AwsCloudHsmClient implements HsmClient {

    static final String DEFAULT_MODULE = "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so";

    private final String defaultLabel;
    private final SigningKey signingKey;

    public AwsCloudHsmClient() {
        this(System.getProperty(CrypkiConsts.PROP_HSM_MODULE_PATH, DEFAULT_MODULE),
                System.getProperty(CrypkiConsts.PROP_HSM_SLOT),
                System.getProperty(CrypkiConsts.PROP_HSM_KEY_LABEL, CrypkiConsts.DEFAULT_HSM_KEY_LABEL),
                System.getProperty(CrypkiConsts.PROP_HSM_PIN_PATH),
                System.getProperty(CrypkiConsts.PROP_HSM_CA_CERT_PATH));
    }

    public AwsCloudHsmClient(String modulePath, String slot, String keyLabel, String pinPath,
            String caCertPath) {
        this.defaultLabel = StringUtil.isEmpty(keyLabel)
                ? CrypkiConsts.DEFAULT_HSM_KEY_LABEL : keyLabel;
        this.signingKey = loadSigningKey(modulePath, slot, this.defaultLabel, pinPath, caCertPath);
    }

    AwsCloudHsmClient(SigningKey signingKey, String defaultLabel) {
        this.signingKey = signingKey;
        this.defaultLabel = defaultLabel;
    }

    @Override
    public SigningKey getSigningKey(String keyId) {
        final String label = resolveLabel(keyId);
        if (!defaultLabel.equals(label) && !signingKey.getIdentifier().equals(label)) {
            throw new CrypkiException("CloudHSM key label is not loaded: " + label
                    + " (configured " + defaultLabel + ")");
        }
        return signingKey;
    }

    String resolveLabel(String requested) {
        if (requested == null || requested.isEmpty() || CrypkiConsts.DEFAULT_KEY_ID.equals(requested)) {
            return defaultLabel;
        }
        return requested;
    }

    static SigningKey loadSigningKey(String modulePath, String slot, String label, String pinPath,
            String caCertPath) {
        if (modulePath == null || !new File(modulePath).isFile()) {
            throw new CrypkiException("AWS CloudHSM PKCS#11 module not found: " + modulePath);
        }
        char[] pin = readPin(pinPath);
        X509Certificate caCertificate = loadCaCertificate(caCertPath);
        try {
            if (cloudHsmJcePresent()) {
                return loadCloudHsmJce(label, pin, caCertificate);
            }
            return loadSunPkcs11(modulePath, slot, label, pin, caCertificate);
        } catch (CrypkiException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new CrypkiException("Unable to load CloudHSM key " + label
                    + ": " + ex.getMessage(), ex);
        } finally {
            java.util.Arrays.fill(pin, '\0');
        }
    }

    static boolean cloudHsmJcePresent() {
        try {
            Class.forName("com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider");
            return true;
        } catch (ClassNotFoundException ex) {
            return false;
        }
    }

    static SigningKey loadCloudHsmJce(String label, char[] pin, X509Certificate caCertificate)
            throws Exception {
        Class<?> providerClass = Class.forName("com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider");
        Provider provider = (Provider) providerClass.getDeclaredConstructor().newInstance();
        if (Security.getProvider(provider.getName()) == null) {
            Security.addProvider(provider);
        }
        if (provider instanceof AuthProvider) {
            ((AuthProvider) provider).login(null, callbacks -> {
                for (javax.security.auth.callback.Callback callback : callbacks) {
                    if (callback instanceof PasswordCallback) {
                        ((PasswordCallback) callback).setPassword(pin);
                    }
                }
            });
        }
        PrivateKey privateKey = loadCloudHsmJcePrivateKey(provider, label, pin);
        if (privateKey == null) {
            throw new CrypkiException("CloudHSM JCE key not found for label " + label);
        }
        return new SigningKey(label, privateKey, caCertificate);
    }

    /**
     * Prefer {@code KeyStoreWithAttributes} so a public/private pair that
     * shares a label (CloudHSM default) still resolves to the private key.
     * {@code KeyStore.getKey(alias)} throws when two objects have that label.
     */
    static PrivateKey loadCloudHsmJcePrivateKey(Provider provider, String label, char[] pin)
            throws Exception {
        PrivateKey byAttributes = loadCloudHsmJcePrivateKeyByAttributes(provider, label, pin);
        if (byAttributes != null) {
            return byAttributes;
        }
        KeyStore keyStore = KeyStore.getInstance(provider.getName(), provider);
        keyStore.load(null, pin);
        return (PrivateKey) keyStore.getKey(label, pin);
    }

    static PrivateKey loadCloudHsmJcePrivateKeyByAttributes(Provider provider, String label,
            char[] pin) {
        try {
            Class<?> ksClass = Class.forName(
                    "com.amazonaws.cloudhsm.jce.provider.KeyStoreWithAttributes");
            Class<?> builderClass = Class.forName(
                    "com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMapBuilder");
            Class<?> attrClass = Class.forName(
                    "com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute");
            Class<?> classType = Class.forName(
                    "com.amazonaws.cloudhsm.jce.provider.attributes.ObjectClassType");
            Object builder = builderClass.getDeclaredConstructor().newInstance();
            Object labelAttr = Enum.valueOf(attrClass.asSubclass(Enum.class), "LABEL");
            Object classAttr = Enum.valueOf(attrClass.asSubclass(Enum.class), "OBJECT_CLASS");
            Object privateClass = Enum.valueOf(classType.asSubclass(Enum.class), "PRIVATE_KEY");
            builderClass.getMethod("put", attrClass, Object.class).invoke(builder, labelAttr, label);
            builderClass.getMethod("put", attrClass, Object.class)
                    .invoke(builder, classAttr, privateClass);
            Object spec = builderClass.getMethod("build").invoke(builder);
            KeyStore keyStore = (KeyStore) ksClass.getMethod("getInstance", String.class, Provider.class)
                    .invoke(null, provider.getName(), provider);
            keyStore.load(null, pin);
            Object key = ksClass.getMethod("getKey", java.security.spec.KeySpec.class)
                    .invoke(keyStore, spec);
            return key instanceof PrivateKey ? (PrivateKey) key : null;
        } catch (ClassNotFoundException ex) {
            return null;
        } catch (Exception ex) {
            throw new CrypkiException("Unable to load CloudHSM JCE private key " + label
                    + ": " + ex.getMessage(), ex);
        }
    }

    static SigningKey loadSunPkcs11(String modulePath, String slot, String label, char[] pin,
            X509Certificate caCertificate) throws Exception {
        Provider provider = pkcs11Provider(modulePath, slot);
        KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
        keyStore.load(null, pin);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(label, pin);
        if (privateKey == null) {
            throw new CrypkiException("CloudHSM PKCS#11 key not found for label " + label
                    + " (install cloudhsm-jce or store a certificate object with the key)");
        }
        return new SigningKey(label, privateKey, caCertificate);
    }

    static Provider pkcs11Provider(String modulePath, String slot) {
        Provider prototype = Security.getProvider("SunPKCS11");
        if (prototype == null) {
            throw new CrypkiException("SunPKCS11 provider is not available");
        }
        String config = pkcs11Config(modulePath, slot);
        try {
            Provider configured = prototype.configure(config);
            if (Security.getProvider(configured.getName()) == null) {
                Security.addProvider(configured);
            }
            return configured;
        } catch (Exception ex) {
            throw new CrypkiException("Unable to configure SunPKCS11 for " + modulePath
                    + ": " + ex.getMessage(), ex);
        }
    }

    static String pkcs11Config(String modulePath, String slot) {
        StringBuilder config = new StringBuilder();
        config.append("--name=AthenzCrypkiHsm\n");
        config.append("library=").append(modulePath).append('\n');
        if (StringUtil.isEmpty(slot)) {
            config.append("slotListIndex=0\n");
        } else {
            config.append("slot=").append(slot).append('\n');
        }
        return config.toString();
    }

    static char[] readPin(String pinPath) {
        if (StringUtil.isEmpty(pinPath)) {
            throw new CrypkiException("Missing " + CrypkiConsts.PROP_HSM_PIN_PATH);
        }
        try {
            String pin = Files.readString(Path.of(pinPath)).strip();
            if (pin.isEmpty()) {
                throw new CrypkiException("CloudHSM PIN file is empty: " + pinPath);
            }
            return pin.toCharArray();
        } catch (CrypkiException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new CrypkiException("Unable to read CloudHSM PIN file: " + pinPath, ex);
        }
    }

    static X509Certificate loadCaCertificate(String caCertPath) {
        if (StringUtil.isEmpty(caCertPath)) {
            throw new CrypkiException("Missing " + CrypkiConsts.PROP_HSM_CA_CERT_PATH);
        }
        try {
            return Crypto.loadX509Certificate(Files.readString(Path.of(caCertPath)));
        } catch (Exception ex) {
            throw new CrypkiException("Unable to load CloudHSM CA certificate: " + caCertPath, ex);
        }
    }
}
