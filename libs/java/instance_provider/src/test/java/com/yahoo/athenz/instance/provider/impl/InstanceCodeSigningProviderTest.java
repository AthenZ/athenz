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
import com.yahoo.athenz.instance.provider.ResourceException;
import io.jsonwebtoken.SignatureAlgorithm;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;

import static com.yahoo.athenz.instance.provider.impl.IdTokenTestsHelper.createOpenIdConfigFile;
import static com.yahoo.athenz.instance.provider.impl.IdTokenTestsHelper.removeOpenIdConfigFile;
import static org.testng.Assert.*;

public class InstanceCodeSigningProviderTest {

    private final File ecPrivateKey = new File("./src/test/resources/unit_test_ec_private.key");
    private final File ecPublicKey = new File("./src/test/resources/unit_test_ec_public.key");

    @Test
    public void testInitializeDefaults() {
        InstanceCodeSigningProvider provider = new InstanceCodeSigningProvider();
        System.setProperty(InstanceCodeSigningProvider.ZTS_PROP_ZTS_OPENID_ISSUER, "https://zts.athenz.io");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceCodeSigningProvider", null, null);
        assertEquals(provider.certValidityTime, 15);
        provider.close();
    }

    @Test
    public void testInitialize() throws IOException {
        InstanceCodeSigningProvider provider = new InstanceCodeSigningProvider();
        File configUri = new File("./src/test/resources/codesigning-openid-uri.json");
        System.setProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_OIDC_PROVIDER_OPENID_CONFIG_URI, "file://" + configUri.getCanonicalPath());
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceCodeSigningProvider", null, null);
        assertEquals(provider.certValidityTime, 15);
        assertEquals(provider.codeSigningOidcProviderJwksUri, "file://src/test/resources/keys.json");
        provider.close();
        System.clearProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_OIDC_PROVIDER_OPENID_CONFIG_URI);

    }

    @Test
    public void testNewAttrValidator() {
        System.setProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_ATTR_VALIDATOR_FACTORY_CLASS, "com.yahoo.athenz.instance.provider.impl.MockAttrValidatorFactory");
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
        ResourceException exc = provider.error("unable to access");
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
        } catch (ResourceException re){
            assertEquals(re.getCode(), ResourceException.FORBIDDEN);
        }
        provider.close();
    }

    @Test
    public void testConfirmInstanceInvalidIdToken() {
        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData("{\"identityToken\": \"abc\"}");
        InstanceCodeSigningProvider provider = new InstanceCodeSigningProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceCodeSigningProvider", null, null);
        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException re) {
            assertEquals(re.getCode(), ResourceException.FORBIDDEN);
        }
        provider.close();
    }

    @Test
    public void testConfirmInstanceInvalidAudience() throws IOException {

        File configFile = new File("./src/test/resources/codesigning-openid.json");
        File jwksUri = new File("./src/test/resources/codesigning-jwks.json");
        createOpenIdConfigFile(configFile, jwksUri, true);

        InstanceCodeSigningProvider provider = new InstanceCodeSigningProvider();
        File configUri = new File("./src/test/resources/codesigning-openid-uri.json");
        System.setProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_OIDC_PROVIDER_OPENID_CONFIG_URI, "file://" + configUri.getCanonicalPath());

        IdToken sampleToken = new IdToken();
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        long now = System.currentTimeMillis() / 1000;
        sampleToken.setExpiryTime(now + 3600);
        sampleToken.setIssueTime(now);
        String testToken = sampleToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData("{\"identityToken\": \"" + testToken + "\"}");
        PublicKey publicKey = Crypto.loadPublicKey(ecPublicKey);

        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceCodeSigningProvider", null, null);
        provider.signingKeyResolver.addPublicKey("eckey1", publicKey);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException re) {
            assertEquals(re.getCode(), ResourceException.FORBIDDEN);
        }
        provider.close();
        removeOpenIdConfigFile(configFile, jwksUri);
        System.clearProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_OIDC_PROVIDER_OPENID_CONFIG_URI);
    }

    @Test
    public void testConfirmInstanceInvalidSubject() throws IOException {

        File configFile = new File("./src/test/resources/codesigning-openid.json");
        File jwksUri = new File("./src/test/resources/codesigning-jwks.json");
        createOpenIdConfigFile(configFile, jwksUri, true);

        InstanceCodeSigningProvider provider = new InstanceCodeSigningProvider();
        File configUri = new File("./src/test/resources/codesigning-openid-uri.json");
        System.setProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_OIDC_PROVIDER_OPENID_CONFIG_URI, "file://" + configUri.getCanonicalPath());
        System.setProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_ATTESTATION_EXPECTED_AUDIENCE, "https://zts.athenz.io");
        IdToken sampleToken = new IdToken();
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        long now = System.currentTimeMillis() / 1000;
        sampleToken.setExpiryTime(now + 3600);
        sampleToken.setIssueTime(now);
        sampleToken.setAudience("https://zts.athenz.io");
        sampleToken.setSubject("athenz.zxz");
        String testToken = sampleToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData("{\"identityToken\": \"" + testToken + "\"}");
        PublicKey publicKey = Crypto.loadPublicKey(ecPublicKey);

        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceCodeSigningProvider", null, null);
        provider.signingKeyResolver.addPublicKey("eckey1", publicKey);
        confirmation.setDomain("athenz");
        confirmation.setService("api");
        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException re) {
            assertEquals(re.getCode(), ResourceException.FORBIDDEN);
        }
        provider.close();
        removeOpenIdConfigFile(configFile, jwksUri);
        System.clearProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_OIDC_PROVIDER_OPENID_CONFIG_URI);
        System.clearProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_ATTESTATION_EXPECTED_AUDIENCE);
    }

    @Test
    public void testConfirmInstanceFailedAttrValidation() throws IOException {

        File configFile = new File("./src/test/resources/codesigning-openid.json");
        File jwksUri = new File("./src/test/resources/codesigning-jwks.json");
        createOpenIdConfigFile(configFile, jwksUri, true);

        InstanceCodeSigningProvider provider = new InstanceCodeSigningProvider();
        File configUri = new File("./src/test/resources/codesigning-openid-uri.json");
        System.setProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_OIDC_PROVIDER_OPENID_CONFIG_URI, "file://" + configUri.getCanonicalPath());
        System.setProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_ATTESTATION_EXPECTED_AUDIENCE, "https://zts.athenz.io");
        System.setProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_ATTR_VALIDATOR_FACTORY_CLASS, "com.yahoo.athenz.instance.provider.impl.MockFailingAttrValidatorFactory");
        IdToken sampleToken = new IdToken();
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        long now = System.currentTimeMillis() / 1000;
        sampleToken.setExpiryTime(now + 3600);
        sampleToken.setIssueTime(now);
        sampleToken.setAudience("https://zts.athenz.io");
        sampleToken.setSubject("athenz.api");
        String testToken = sampleToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData("{\"identityToken\": \"" + testToken + "\"}");
        PublicKey publicKey = Crypto.loadPublicKey(ecPublicKey);

        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceCodeSigningProvider", null, null);
        provider.signingKeyResolver.addPublicKey("eckey1", publicKey);
        confirmation.setDomain("athenz");
        confirmation.setService("api");
        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException re) {
            assertEquals(re.getCode(), ResourceException.FORBIDDEN);
        }
        provider.close();
        removeOpenIdConfigFile(configFile, jwksUri);
        System.clearProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_OIDC_PROVIDER_OPENID_CONFIG_URI);
        System.clearProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_ATTESTATION_EXPECTED_AUDIENCE);
        System.clearProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_ATTR_VALIDATOR_FACTORY_CLASS);
    }

    @Test
    public void testConfirmInstance() throws IOException {

        File configFile = new File("./src/test/resources/codesigning-openid.json");
        File jwksUri = new File("./src/test/resources/codesigning-jwks.json");
        createOpenIdConfigFile(configFile, jwksUri, true);

        InstanceCodeSigningProvider provider = new InstanceCodeSigningProvider();
        File configUri = new File("./src/test/resources/codesigning-openid-uri.json");
        System.setProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_OIDC_PROVIDER_OPENID_CONFIG_URI, "file://" + configUri.getCanonicalPath());
        System.setProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_ATTESTATION_EXPECTED_AUDIENCE, "https://zts.athenz.io");
        System.setProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_ATTR_VALIDATOR_FACTORY_CLASS, "com.yahoo.athenz.instance.provider.impl.MockAttrValidatorFactory");
        IdToken sampleToken = new IdToken();
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        long now = System.currentTimeMillis() / 1000;
        sampleToken.setExpiryTime(now + 3600);
        sampleToken.setIssueTime(now);
        sampleToken.setAudience("https://zts.athenz.io");
        sampleToken.setSubject("athenz.api");
        String testToken = sampleToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData("{\"identityToken\": \"" + testToken + "\"}");
        PublicKey publicKey = Crypto.loadPublicKey(ecPublicKey);

        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceCodeSigningProvider", null, null);
        provider.signingKeyResolver.addPublicKey("eckey1", publicKey);
        confirmation.setDomain("athenz");
        confirmation.setService("api");
        provider.confirmInstance(confirmation);
        assertEquals(confirmation.getAttributes().size(), 3);

        assertEquals(confirmation.getAttributes().get(InstanceProvider.ZTS_CERT_USAGE), "codeSigning");
        assertEquals(confirmation.getAttributes().get(InstanceProvider.ZTS_CERT_REFRESH), "false");
        assertEquals(confirmation.getAttributes().get(InstanceProvider.ZTS_CERT_EXPIRY_TIME), "15");

        provider.close();
        removeOpenIdConfigFile(configFile, jwksUri);
        System.clearProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_OIDC_PROVIDER_OPENID_CONFIG_URI);
        System.clearProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_ATTESTATION_EXPECTED_AUDIENCE);
        System.clearProperty(InstanceCodeSigningProvider.ZTS_PROP_CODE_SIGNING_ATTR_VALIDATOR_FACTORY_CLASS);
    }
}