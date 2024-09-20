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
package com.yahoo.athenz.instance.provider.impl;

import com.yahoo.athenz.auth.token.IdToken;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.instance.provider.AttrValidator;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.ProviderResourceException;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Objects;

import static com.yahoo.athenz.instance.provider.impl.IdTokenTestsHelper.*;
import static org.testng.Assert.*;

public class InstanceCodeSigningProviderTest {

    private final File ecPrivateKey = new File("./src/test/resources/unit_test_ec_private.key");
    private final File ecPublicKey = new File("./src/test/resources/unit_test_ec_public.key");

    private final ClassLoader classLoader = this.getClass().getClassLoader();

    @Test
    public void testInitializeDefaults() {
        InstanceCodeSigningProvider provider = new InstanceCodeSigningProvider();
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks_empty.json")).toString();
        System.setProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_OIDC_PROVIDER_JWKS_URI, jwksUri);
        System.setProperty(InstanceCodeSigningProvider.ZTS_PROP_ZTS_OPENID_ISSUER, "https://zts.athenz.io");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceCodeSigningProvider", null, null);
        assertEquals(provider.certValidityTime, 15);
        provider.close();
        System.clearProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_OIDC_PROVIDER_JWKS_URI);
    }

    @Test
    public void testInitialize() throws IOException {
        InstanceCodeSigningProvider provider = new InstanceCodeSigningProvider();
        File configUri = new File("./src/test/resources/codesigning-openid-uri.json");
        System.setProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_OIDC_PROVIDER_OPENID_CONFIG_URI,
                "file://" + configUri.getCanonicalPath());
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks_empty.json")).toString();
        System.setProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_OIDC_PROVIDER_JWKS_URI, jwksUri);
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceCodeSigningProvider", null, null);
        assertEquals(provider.certValidityTime, 15);
        provider.close();
        System.clearProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_OIDC_PROVIDER_OPENID_CONFIG_URI);
        System.clearProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_OIDC_PROVIDER_JWKS_URI);
    }

    @Test
    public void testNewAttrValidator() {
        System.setProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_ATTR_VALIDATOR_FACTORY_CLASS,
                "com.yahoo.athenz.instance.provider.impl.MockAttrValidatorFactory");
        AttrValidator attrValidator = InstanceCodeSigningProvider.newAttrValidator(null);
        assertNotNull(attrValidator);
        assertTrue(attrValidator.confirm(null));
        System.clearProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_ATTR_VALIDATOR_FACTORY_CLASS);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testNewAttrValidatorFail() {
        System.setProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_ATTR_VALIDATOR_FACTORY_CLASS, "NoClass");
        InstanceCodeSigningProvider.newAttrValidator(null);
        System.clearProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_ATTR_VALIDATOR_FACTORY_CLASS);
    }

    @Test
    public void testGetProviderScheme() {
        assertEquals(InstanceProvider.Scheme.CLASS, new InstanceCodeSigningProvider().getProviderScheme());
    }

    @Test
    public void testError() {
        InstanceCodeSigningProvider provider = new InstanceCodeSigningProvider();
        ProviderResourceException exc = provider.error("unable to access");
        assertEquals(exc.getCode(), 403);
        assertEquals(exc.getMessage(), "ResourceException (403): unable to access");
        provider.close();
    }

    @Test
    public void testRefreshInstance() {
        InstanceCodeSigningProvider provider = new InstanceCodeSigningProvider();
        InstanceConfirmation confirmation = new InstanceConfirmation();
        try {
            provider.refreshInstance(confirmation);
            fail();
        } catch (ProviderResourceException re){
            assertEquals(re.getCode(), ProviderResourceException.FORBIDDEN);
        }
        provider.close();
    }

    @Test
    public void testConfirmInstanceInvalidIdToken() {
        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData("{\"identityToken\": \"abc\"}");
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks_empty.json")).toString();
        System.setProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_OIDC_PROVIDER_JWKS_URI, jwksUri);
        InstanceCodeSigningProvider provider = new InstanceCodeSigningProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceCodeSigningProvider", null, null);
        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException re) {
            assertEquals(re.getCode(), ProviderResourceException.FORBIDDEN);
        }
        provider.close();
        System.clearProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_OIDC_PROVIDER_JWKS_URI);
    }

    @Test
    public void testConfirmInstanceInvalidAudience() throws IOException {

        PublicKey publicKey = Crypto.loadPublicKey(ecPublicKey);
        File configFile = new File("./src/test/resources/codesigning-openid.json");
        File jwksUri = new File("./src/test/resources/codesigning-jwks.json");
        createOpenIdConfigFileWithKey(configFile, jwksUri, true, (ECPublicKey) publicKey);

        InstanceCodeSigningProvider provider = new InstanceCodeSigningProvider();
        File configUri = new File("./src/test/resources/codesigning-openid-uri.json");
        System.setProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_OIDC_PROVIDER_OPENID_CONFIG_URI,
                "file://" + configUri.getCanonicalPath());

        IdToken sampleToken = new IdToken();
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        long now = System.currentTimeMillis() / 1000;
        sampleToken.setExpiryTime(now + 3600);
        sampleToken.setIssueTime(now);
        String testToken = sampleToken.getSignedToken(privateKey, "eckey1", "ES256");
        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData("{\"identityToken\": \"" + testToken + "\"}");

        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceCodeSigningProvider", null, null);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException re) {
            assertEquals(re.getCode(), ProviderResourceException.FORBIDDEN);
        }
        provider.close();
        removeOpenIdConfigFile(configFile, jwksUri);
        System.clearProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_OIDC_PROVIDER_OPENID_CONFIG_URI);
    }

    @Test
    public void testConfirmInstanceInvalidSubject() throws IOException {

        PublicKey publicKey = Crypto.loadPublicKey(ecPublicKey);
        File configFile = new File("./src/test/resources/codesigning-openid.json");
        File jwksUri = new File("./src/test/resources/codesigning-jwks.json");
        createOpenIdConfigFileWithKey(configFile, jwksUri, true, (ECPublicKey) publicKey);

        InstanceCodeSigningProvider provider = new InstanceCodeSigningProvider();
        System.setProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_OIDC_PROVIDER_OPENID_CONFIG_URI,
                "file://" + configFile.getCanonicalPath());
        System.setProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_ATTESTATION_EXPECTED_AUDIENCE,
                "https://zts.athenz.io");
        IdToken sampleToken = new IdToken();
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        long now = System.currentTimeMillis() / 1000;
        sampleToken.setExpiryTime(now + 3600);
        sampleToken.setIssueTime(now);
        sampleToken.setAudience("https://zts.athenz.io");
        sampleToken.setSubject("athenz.zxz");
        String testToken = sampleToken.getSignedToken(privateKey, "eckey1", "ES256");
        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData("{\"identityToken\": \"" + testToken + "\"}");

        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceCodeSigningProvider", null, null);
        confirmation.setDomain("athenz");
        confirmation.setService("api");
        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException re) {
            assertEquals(re.getCode(), ProviderResourceException.FORBIDDEN);
        }
        provider.close();
        removeOpenIdConfigFile(configFile, jwksUri);
        System.clearProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_OIDC_PROVIDER_OPENID_CONFIG_URI);
        System.clearProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_ATTESTATION_EXPECTED_AUDIENCE);
    }

    @Test
    public void testConfirmInstanceFailedAttrValidation() throws IOException {

        PublicKey publicKey = Crypto.loadPublicKey(ecPublicKey);
        File configFile = new File("./src/test/resources/codesigning-openid.json");
        File jwksUri = new File("./src/test/resources/codesigning-jwks.json");
        createOpenIdConfigFileWithKey(configFile, jwksUri, true, (ECPublicKey) publicKey);

        InstanceCodeSigningProvider provider = new InstanceCodeSigningProvider();
        System.setProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_OIDC_PROVIDER_OPENID_CONFIG_URI,
                "file://" + configFile.getCanonicalPath());
        System.setProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_ATTESTATION_EXPECTED_AUDIENCE,
                "https://zts.athenz.io");
        System.setProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_ATTR_VALIDATOR_FACTORY_CLASS,
                "com.yahoo.athenz.instance.provider.impl.MockFailingAttrValidatorFactory");
        IdToken sampleToken = new IdToken();
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        long now = System.currentTimeMillis() / 1000;
        sampleToken.setExpiryTime(now + 3600);
        sampleToken.setIssueTime(now);
        sampleToken.setAudience("https://zts.athenz.io");
        sampleToken.setSubject("athenz.api");
        String testToken = sampleToken.getSignedToken(privateKey, "eckey1", "ES256");
        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData("{\"identityToken\": \"" + testToken + "\"}");

        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceCodeSigningProvider", null, null);
        confirmation.setDomain("athenz");
        confirmation.setService("api");
        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException re) {
            assertEquals(re.getCode(), ProviderResourceException.FORBIDDEN);
        }
        provider.close();
        removeOpenIdConfigFile(configFile, jwksUri);
        System.clearProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_OIDC_PROVIDER_OPENID_CONFIG_URI);
        System.clearProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_ATTESTATION_EXPECTED_AUDIENCE);
        System.clearProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_ATTR_VALIDATOR_FACTORY_CLASS);
    }

    @Test
    public void testConfirmInstance() throws IOException, ProviderResourceException {

        File configFile = new File("./src/test/resources/codesigning-openid.json");
        File jwksUriFile = new File("./src/test/resources/codesigning-jwks.json");
        String jwksUri = createOpenIdConfigFile(configFile, jwksUriFile, true);

        System.setProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_OIDC_PROVIDER_JWKS_URI, jwksUri);

        InstanceCodeSigningProvider provider = new InstanceCodeSigningProvider();
        System.setProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_OIDC_PROVIDER_OPENID_CONFIG_URI,
                "file://" + configFile.getCanonicalPath());
        System.setProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_ATTESTATION_EXPECTED_AUDIENCE,
                "https://zts.athenz.io");
        System.setProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_ATTR_VALIDATOR_FACTORY_CLASS,
                "com.yahoo.athenz.instance.provider.impl.MockAttrValidatorFactory");
        IdToken sampleToken = new IdToken();
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        long now = System.currentTimeMillis() / 1000;
        sampleToken.setExpiryTime(now + 3600);
        sampleToken.setIssueTime(now);
        sampleToken.setAudience("https://zts.athenz.io");
        sampleToken.setSubject("athenz.api");
        String testToken = sampleToken.getSignedToken(privateKey, "eckey1", "ES256");
        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData("{\"identityToken\": \"" + testToken + "\"}");

        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceCodeSigningProvider", null, null);
        confirmation.setDomain("athenz");
        confirmation.setService("api");
        provider.confirmInstance(confirmation);
        assertEquals(confirmation.getAttributes().size(), 3);

        assertEquals(confirmation.getAttributes().get(InstanceProvider.ZTS_CERT_USAGE), "codeSigning");
        assertEquals(confirmation.getAttributes().get(InstanceProvider.ZTS_CERT_REFRESH), "false");
        assertEquals(confirmation.getAttributes().get(InstanceProvider.ZTS_CERT_EXPIRY_TIME), "15");

        provider.close();
        removeOpenIdConfigFile(configFile, jwksUriFile);
        System.clearProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_OIDC_PROVIDER_OPENID_CONFIG_URI);
        System.clearProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_ATTESTATION_EXPECTED_AUDIENCE);
        System.clearProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_ATTR_VALIDATOR_FACTORY_CLASS);
        System.setProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_OIDC_PROVIDER_JWKS_URI, jwksUri);
    }
}
