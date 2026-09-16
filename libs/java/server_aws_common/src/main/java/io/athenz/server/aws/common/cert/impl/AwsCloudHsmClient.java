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
import com.yahoo.athenz.crypki.kms.KmsCaCertificateStore;
import com.yahoo.athenz.crypki.signer.SigningKey;
import org.eclipse.jetty.util.StringUtil;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.lang.reflect.InvocationTargetException;
import java.security.AuthProvider;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.security.auth.callback.PasswordCallback;

/**
 * CloudHSM {@link HsmClient}: CloudHSM JCE when present, otherwise
 * SunPKCS11. The CA PEM is loaded from disk. The private key never
 * leaves the HSM. Optional {@code athenz.crypki.hsm.ca_cert_map_path}
 * loads one HSM label + CA PEM per Athenz signer key id.
 *
 * <p>SunPKCS11's PKCS#11 {@code KeyStore} only exposes private keys that
 * have a matching certificate object, so CloudHSM JCE
 * ({@code /opt/cloudhsm/java/cloudhsm-jce-*.jar}) is required for a
 * label-only sign key.
 */
public class AwsCloudHsmClient implements HsmClient {

    static final String DEFAULT_MODULE = "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so";

    private final String defaultLabel;
    private final KmsCaCertificateStore caCertificates;
    private final Map<String, SigningKey> keysByLabel;

    public AwsCloudHsmClient() {
        this(System.getProperty(CrypkiConsts.PROP_HSM_MODULE_PATH, DEFAULT_MODULE),
                System.getProperty(CrypkiConsts.PROP_HSM_SLOT),
                System.getProperty(CrypkiConsts.PROP_HSM_KEY_LABEL, CrypkiConsts.DEFAULT_HSM_KEY_LABEL),
                System.getProperty(CrypkiConsts.PROP_HSM_PIN_PATH),
                System.getProperty(CrypkiConsts.PROP_HSM_CA_CERT_PATH));
    }

    public AwsCloudHsmClient(String modulePath, String slot, String keyLabel, String pinPath,
            String caCertPath) {
        this(modulePath, slot, keyLabel, pinPath, new KmsCaCertificateStore(caCertPath,
                System.getProperty(CrypkiConsts.PROP_HSM_CA_CERT_MAP_PATH),
                CrypkiConsts.PROP_HSM_CA_CERT_PATH));
    }

    AwsCloudHsmClient(String modulePath, String slot, String keyLabel, String pinPath,
            KmsCaCertificateStore caCertificates) {
        this.defaultLabel = StringUtil.isEmpty(keyLabel)
                ? CrypkiConsts.DEFAULT_HSM_KEY_LABEL : keyLabel;
        this.caCertificates = caCertificates;
        this.keysByLabel = loadSigningKeys(modulePath, slot, pinPath, this.defaultLabel,
                caCertificates);
    }

    AwsCloudHsmClient(SigningKey signingKey, String defaultLabel) {
        this(singleKey(signingKey, defaultLabel), defaultLabel,
                new KmsCaCertificateStore(null, null, CrypkiConsts.PROP_HSM_CA_CERT_PATH));
    }

    AwsCloudHsmClient(Map<String, SigningKey> keysByLabel, String defaultLabel,
            KmsCaCertificateStore caCertificates) {
        this.defaultLabel = defaultLabel;
        this.caCertificates = caCertificates;
        this.keysByLabel = new LinkedHashMap<>(keysByLabel);
        if (!this.keysByLabel.containsKey(defaultLabel) && !keysByLabel.isEmpty()) {
            this.keysByLabel.put(defaultLabel, keysByLabel.values().iterator().next());
        }
    }

    @Override
    public SigningKey getSigningKey(String keyId) {
        final String label = resolveLabel(keyId);
        SigningKey signingKey = keysByLabel.get(label);
        if (signingKey == null) {
            throw new CrypkiException("CloudHSM key label is not loaded: " + label
                    + " (configured " + defaultLabel + ")");
        }
        return signingKey;
    }

    String resolveLabel(String requested) {
        if (requested == null || requested.isEmpty() || CrypkiConsts.DEFAULT_KEY_ID.equals(requested)) {
            return defaultLabel;
        }
        return mappedLabel(requested, defaultLabel, caCertificates);
    }

    static Map<String, SigningKey> loadSigningKeys(String modulePath, String slot, String pinPath,
            String defaultLabel, KmsCaCertificateStore caCertificates) {
        char[] pin = readPin(pinPath);
        try {
            Provider jceProvider = null;
            if (cloudHsmJcePresent()) {
                jceProvider = cloudHsmJceProvider();
                loginCloudHsmJce(jceProvider, pin);
            }
            Map<String, SigningKey> loaded = new LinkedHashMap<>();
            loaded.put(defaultLabel, loadSigningKey(jceProvider, modulePath, slot, defaultLabel, pin,
                    caCertificates.get(null)));
            for (Map.Entry<String, String> entry : caCertificates.getCertPathsByKeyId().entrySet()) {
                String label = mappedLabel(entry.getKey(), defaultLabel, caCertificates);
                X509Certificate caCertificate = caCertificates.get(entry.getKey());
                SigningKey existing = loaded.get(label);
                if (existing != null) {
                    if (!existing.getCaCertificate().equals(caCertificate)) {
                        throw new CrypkiException("CloudHSM label " + label
                                + " is mapped to more than one CA certificate");
                    }
                    continue;
                }
                loaded.put(label, loadSigningKey(jceProvider, modulePath, slot, label, pin,
                        caCertificate));
            }
            return loaded;
        } catch (CrypkiException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new CrypkiException("Unable to load CloudHSM keys: " + ex.getMessage(), ex);
        } finally {
            java.util.Arrays.fill(pin, '\0');
        }
    }

    static String mappedLabel(String athenzKeyId, String defaultLabel,
            KmsCaCertificateStore caCertificates) {
        String mapped = caCertificates.resolveCloudKeyId(athenzKeyId);
        if (StringUtil.isEmpty(mapped) || CrypkiConsts.DEFAULT_KEY_ID.equals(mapped)) {
            return defaultLabel;
        }
        return mapped;
    }

    static Map<String, SigningKey> singleKey(SigningKey signingKey, String defaultLabel) {
        Map<String, SigningKey> keys = new LinkedHashMap<>();
        keys.put(signingKey.getIdentifier(), signingKey);
        keys.putIfAbsent(defaultLabel, signingKey);
        return keys;
    }

    static SigningKey loadSigningKey(String modulePath, String slot, String label, String pinPath,
            String caCertPath) {
        return loadSigningKey(modulePath, slot, label, pinPath, loadCaCertificate(caCertPath));
    }

    static SigningKey loadSigningKey(String modulePath, String slot, String label, String pinPath,
            X509Certificate caCertificate) {
        char[] pin = readPin(pinPath);
        try {
            if (cloudHsmJcePresent()) {
                return loadCloudHsmJce(label, pin, caCertificate);
            }
            return loadSigningKey(null, modulePath, slot, label, pin, caCertificate);
        } catch (CrypkiException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new CrypkiException("Unable to load CloudHSM key " + label
                    + ": " + ex.getMessage(), ex);
        } finally {
            java.util.Arrays.fill(pin, '\0');
        }
    }

    static SigningKey loadSigningKey(Provider jceProvider, String modulePath, String slot,
            String label, char[] pin, X509Certificate caCertificate) throws Exception {
        if (jceProvider != null) {
            return signingKeyFromCloudHsmJce(jceProvider, label, pin, caCertificate);
        }
        if (modulePath == null || !new File(modulePath).isFile()) {
            throw new CrypkiException("AWS CloudHSM PKCS#11 module not found: " + modulePath);
        }
        return loadSunPkcs11(modulePath, slot, label, pin, caCertificate);
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
        Provider provider = cloudHsmJceProvider();
        loginCloudHsmJce(provider, pin);
        return signingKeyFromCloudHsmJce(provider, label, pin, caCertificate);
    }

    static SigningKey signingKeyFromCloudHsmJce(Provider provider, String label, char[] pin,
            X509Certificate caCertificate) throws Exception {
        PrivateKey privateKey = loadCloudHsmJcePrivateKey(provider, label, pin);
        if (privateKey == null) {
            throw new CrypkiException("CloudHSM JCE key not found for label " + label);
        }
        return new SigningKey(label, privateKey, caCertificate);
    }

    /**
     * CloudHSM JCE 5.x allows one HSM connection per process. A second
     * {@code new CloudHsmProvider()} throws "already initialized", so
     * reuse the registered provider when loading more than one label.
     */
    static Provider cloudHsmJceProvider() throws Exception {
        Class<?> providerClass = Class.forName("com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider");
        Provider existing = findRegisteredCloudHsmProvider(providerClass);
        if (existing != null) {
            return existing;
        }
        return createCloudHsmProvider(providerClass);
    }

    static Provider createCloudHsmProvider(Class<?> providerClass) throws Exception {
        try {
            Provider created = (Provider) providerClass.getDeclaredConstructor().newInstance();
            Provider registered = Security.getProvider(created.getName());
            if (registered != null) {
                return registered;
            }
            Security.addProvider(created);
            return created;
        } catch (InvocationTargetException ex) {
            Provider recovered = findRegisteredCloudHsmProvider(providerClass);
            if (recovered != null) {
                return recovered;
            }
            if (ex.getCause() instanceof Exception) {
                throw (Exception) ex.getCause();
            }
            throw ex;
        }
    }

    static Provider findRegisteredCloudHsmProvider(Class<?> providerClass) {
        for (String name : cloudHsmProviderNames(providerClass)) {
            Provider provider = Security.getProvider(name);
            if (providerClass.isInstance(provider)) {
                return provider;
            }
        }
        for (Provider provider : Security.getProviders()) {
            if (providerClass.isInstance(provider)) {
                return provider;
            }
        }
        return null;
    }

    static String[] cloudHsmProviderNames(Class<?> providerClass) {
        try {
            Object value = providerClass.getField("PROVIDER_NAME").get(null);
            if (value instanceof String && !((String) value).isEmpty()) {
                return new String[]{(String) value, "CloudHSM", "CloudHsmProvider"};
            }
        } catch (Exception ignored) {
        }
        return new String[]{"CloudHSM", "CloudHsmProvider"};
    }

    static void loginCloudHsmJce(Provider provider, char[] pin) throws Exception {
        if (!(provider instanceof AuthProvider)) {
            return;
        }
        try {
            ((AuthProvider) provider).login(null, callbacks -> {
                for (javax.security.auth.callback.Callback callback : callbacks) {
                    if (callback instanceof PasswordCallback) {
                        ((PasswordCallback) callback).setPassword(pin);
                    }
                }
            });
        } catch (Exception ex) {
            if (alreadyConnected(ex)) {
                return;
            }
            throw ex;
        }
    }

    /**
     * CloudHSM JCE 5 reports a second {@code login} as
     * {@code AccountAlreadyLoggedInException} ("already logged in").
     * Constructing a second provider uses "already initialized".
     */
    static boolean alreadyConnected(Throwable ex) {
        if (ex == null) {
            return false;
        }
        if ("AccountAlreadyLoggedInException".equals(ex.getClass().getSimpleName())) {
            return true;
        }
        String message = ex.getMessage();
        if (message == null) {
            return false;
        }
        String lower = message.toLowerCase();
        return lower.contains("already initialized") || lower.contains("already logged in");
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

    /**
     * CloudHSM Client SDK 5: {@code KeyAttributesMapBuilder.put(LABEL/OBJECT_CLASS)}
     * and {@code KeyStoreWithAttributes.getKey(KeyAttributesMap)}.
     */
    static PrivateKey loadCloudHsmJcePrivateKeyByAttributes(Provider provider, String label,
            char[] pin) {
        try {
            Class<?> ksClass = Class.forName(
                    "com.amazonaws.cloudhsm.jce.provider.KeyStoreWithAttributes");
            Class<?> mapClass = Class.forName(
                    "com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMap");
            Class<?> builderClass = Class.forName(
                    "com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMapBuilder");
            Class<?> attrClass = Class.forName(
                    "com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute");
            Class<?> classType = Class.forName(
                    "com.amazonaws.cloudhsm.jce.provider.attributes.ObjectClassType");
            Object spec = cloudHsmKeyAttributes(builderClass, attrClass, classType, label);
            Object keyStore = ksClass.getMethod("getInstance", String.class).invoke(null, "CloudHSM");
            ksClass.getMethod("load", java.io.InputStream.class, char[].class)
                    .invoke(keyStore, null, pin);
            Object key = invokeCloudHsmGetKey(ksClass, keyStore, spec, mapClass);
            return key instanceof PrivateKey ? (PrivateKey) key : null;
        } catch (ClassNotFoundException ex) {
            return null;
        } catch (Exception ex) {
            throw new CrypkiException("Unable to load CloudHSM JCE private key " + label
                    + ": " + ex.getMessage(), ex);
        }
    }

    /**
     * SDK 5.16+ uses {@code getKey(KeySpec)}; older jars used
     * {@code getKey(KeyAttributesMap)}. {@code KeyAttributesMap} implements
     * {@code KeySpec} on current CloudHSM JCE.
     */
    static Object invokeCloudHsmGetKey(Class<?> ksClass, Object keyStore, Object spec,
            Class<?> mapClass) throws Exception {
        try {
            return ksClass.getMethod("getKey", java.security.spec.KeySpec.class)
                    .invoke(keyStore, spec);
        } catch (NoSuchMethodException ex) {
            return ksClass.getMethod("getKey", mapClass).invoke(keyStore, spec);
        }
    }

    static Object cloudHsmKeyAttributes(Class<?> builderClass, Class<?> attrClass,
            Class<?> classType, String label) throws Exception {
        Object builder = builderClass.getDeclaredConstructor().newInstance();
        Object labelAttr = Enum.valueOf(attrClass.asSubclass(Enum.class), "LABEL");
        Object classAttr = Enum.valueOf(attrClass.asSubclass(Enum.class), "OBJECT_CLASS");
        Object privateClass = Enum.valueOf(classType.asSubclass(Enum.class), "PRIVATE_KEY");
        builderClass.getMethod("put", attrClass, Object.class).invoke(builder, labelAttr, label);
        builderClass.getMethod("put", attrClass, Object.class)
                .invoke(builder, classAttr, privateClass);
        return builderClass.getMethod("build").invoke(builder);
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
