/*
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package io.athenz.server.aws.common.creds.impl;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.ServerResourceException;
import io.athenz.server.aws.common.creds.AwsCredentialsProviderFactory;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.regions.Region;
import software.amazon.rolesanywhere.plugin.RolesAnywhereCredentialsProvider;
import software.amazon.rolesanywhere.plugin.X509Identity;
import software.amazon.rolesanywhere.plugin.X509IdentityProvider;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 * Creates an IAM Roles Anywhere credentials provider for ZTS STS calls.
 * Explicit PEM paths take precedence over the configured server key store.
 * The identity is reloaded when the provider refreshes its credentials.
 */
public class RolesAnywhereCredentialsProviderFactory implements AwsCredentialsProviderFactory {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(RolesAnywhereCredentialsProviderFactory.class);

    static final String PROP_PREFIX = "athenz.zts.rolesanywhere.";

    static final String PROP_CERT_PATH        = PROP_PREFIX + "cert_path";
    static final String PROP_KEY_PATH         = PROP_PREFIX + "key_path";
    static final String PROP_KEY_ALGORITHM    = PROP_PREFIX + "key_algorithm";
    static final String PROP_TRUST_ANCHOR_ARN = PROP_PREFIX + "trust_anchor_arn";
    static final String PROP_PROFILE_ARN      = PROP_PREFIX + "profile_arn";
    static final String PROP_ROLE_ARN         = PROP_PREFIX + "role_arn";
    static final String PROP_REGION           = PROP_PREFIX + "region";

    static final String PROP_KEYSTORE_PATH     = PROP_PREFIX + "keystore_path";
    static final String PROP_KEYSTORE_TYPE     = PROP_PREFIX + "keystore_type";
    static final String PROP_KEYSTORE_PASSWORD = PROP_PREFIX + "keystore_password";
    static final String PROP_KEYSTORE_PASSWORD_APPNAME      = PROP_PREFIX + "keystore_password_appname";
    static final String PROP_KEYSTORE_PASSWORD_KEYGROUPNAME = PROP_PREFIX + "keystore_password_keygroupname";
    static final String PROP_KEYSTORE_ALIAS    = PROP_PREFIX + "keystore_alias";

    static final String ZTS_PROP_AWS_REGION_NAME = "athenz.zts.aws_region_name";

    // Fall back to the server key store settings when no provider-specific setting is supplied.
    static final String ATHENZ_PROP_KEYSTORE_PATH     = "athenz.ssl_key_store";
    static final String ATHENZ_PROP_KEYSTORE_TYPE     = "athenz.ssl_key_store_type";
    static final String ATHENZ_PROP_KEYSTORE_PASSWORD = "athenz.ssl_key_store_password";
    static final String ATHENZ_PROP_KEYSTORE_PASSWORD_APPNAME      = "athenz.ssl_key_store_password_appname";
    static final String ATHENZ_PROP_KEYSTORE_PASSWORD_KEYGROUPNAME = "athenz.ssl_key_store_password_keygroupname";

    static final String DEFAULT_KEY_ALGORITHM = "RSA";
    static final String DEFAULT_KEYSTORE_TYPE = "PKCS12";

    private static final char[] EMPTY_PASSWORD = "".toCharArray();

    PrivateKeyStore privateKeyStore;

    @Override
    public void setPrivateKeyStore(PrivateKeyStore privateKeyStore) {
        this.privateKeyStore = privateKeyStore;
    }

    @Override
    public AwsCredentialsProvider create() throws ServerResourceException {

        final String trustAnchorArn = requiredProperty(PROP_TRUST_ANCHOR_ARN);
        final String profileArn = requiredProperty(PROP_PROFILE_ARN);
        final String roleArn = requiredProperty(PROP_ROLE_ARN);
        final String region = regionName();

        LOGGER.info("creating Roles Anywhere credentials provider: role={} region={}", roleArn, region);

        return RolesAnywhereCredentialsProvider.builder()
                .identityProvider(identityProvider())
                .trustAnchorArn(trustAnchorArn)
                .profileArn(profileArn)
                .roleArn(roleArn)
                .region(Region.of(region))
                .build();
    }

    String regionName() throws ServerResourceException {
        final String region = System.getProperty(PROP_REGION, System.getProperty(ZTS_PROP_AWS_REGION_NAME));
        if (StringUtil.isEmpty(region)) {
            throw new ServerResourceException(ServerResourceException.INTERNAL_SERVER_ERROR,
                    "missing required property: " + PROP_REGION + " or " + ZTS_PROP_AWS_REGION_NAME);
        }
        return region;
    }

    X509IdentityProvider identityProvider() throws ServerResourceException {

        final String certPath = System.getProperty(PROP_CERT_PATH);
        if (!StringUtil.isEmpty(certPath)) {
            final String keyPath = requiredProperty(PROP_KEY_PATH);
            final String keyAlgorithm = System.getProperty(PROP_KEY_ALGORITHM, DEFAULT_KEY_ALGORITHM);
            return X509IdentityProvider.fromFiles(Paths.get(certPath), Paths.get(keyPath), keyAlgorithm);
        }

        final String keyStorePath = System.getProperty(PROP_KEYSTORE_PATH,
                System.getProperty(ATHENZ_PROP_KEYSTORE_PATH));
        if (StringUtil.isEmpty(keyStorePath)) {
            throw new ServerResourceException(ServerResourceException.INTERNAL_SERVER_ERROR,
                    "no client identity configured: set " + PROP_CERT_PATH + " or " + PROP_KEYSTORE_PATH);
        }

        final String keyStoreType = System.getProperty(PROP_KEYSTORE_TYPE,
                System.getProperty(ATHENZ_PROP_KEYSTORE_TYPE, DEFAULT_KEYSTORE_TYPE));
        final String alias = System.getProperty(PROP_KEYSTORE_ALIAS);

        // Resolve the password on each refresh to pick up key store rotation.
        return () -> {
            final char[] password = keyStorePassword();
            try (InputStream in = Files.newInputStream(Paths.get(keyStorePath))) {
                KeyStore keyStore = KeyStore.getInstance(keyStoreType);
                keyStore.load(in, password);
                return identityFromKeyStore(keyStore, alias, password);
            } catch (Exception ex) {
                throw SdkClientException.create("unable to load client identity from " + keyStorePath, ex);
            }
        };
    }

    char[] keyStorePassword() {
        final String password = System.getProperty(PROP_KEYSTORE_PASSWORD,
                System.getProperty(ATHENZ_PROP_KEYSTORE_PASSWORD));
        if (password == null) {
            return EMPTY_PASSWORD;
        }
        if (privateKeyStore == null) {
            return password.toCharArray();
        }
        final String appName = System.getProperty(PROP_KEYSTORE_PASSWORD_APPNAME,
                System.getProperty(ATHENZ_PROP_KEYSTORE_PASSWORD_APPNAME));
        final String keygroupName = System.getProperty(PROP_KEYSTORE_PASSWORD_KEYGROUPNAME,
                System.getProperty(ATHENZ_PROP_KEYSTORE_PASSWORD_KEYGROUPNAME));
        return privateKeyStore.getSecret(appName, keygroupName, password);
    }

    static X509Identity identityFromKeyStore(KeyStore keyStore, final String configuredAlias,
            char[] password) throws Exception {

        final String alias = (configuredAlias != null) ? configuredAlias : firstKeyAlias(keyStore);
        if (alias == null) {
            throw new IllegalArgumentException("key store contains no private key entry");
        }

        final PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password);
        if (privateKey == null) {
            throw new IllegalArgumentException("key store has no private key for alias: " + alias);
        }

        final Certificate[] chain = keyStore.getCertificateChain(alias);
        if (chain == null || chain.length == 0) {
            throw new IllegalArgumentException("key store has no certificate for alias: " + alias);
        }

        List<X509Certificate> intermediates = new ArrayList<>();
        for (int i = 1; i < chain.length; i++) {
            intermediates.add((X509Certificate) chain[i]);
        }

        // A key store may return a shared key handle; the identity must not destroy it.
        return X509Identity.createWithoutDestroyingKey((X509Certificate) chain[0], privateKey, intermediates);
    }

    static String firstKeyAlias(KeyStore keyStore) throws Exception {
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            final String alias = aliases.nextElement();
            if (keyStore.isKeyEntry(alias)) {
                return alias;
            }
        }
        return null;
    }

    static String requiredProperty(final String name) throws ServerResourceException {
        final String value = System.getProperty(name);
        if (StringUtil.isEmpty(value)) {
            throw new ServerResourceException(ServerResourceException.INTERNAL_SERVER_ERROR,
                    "missing required property: " + name);
        }
        return value;
    }
}
