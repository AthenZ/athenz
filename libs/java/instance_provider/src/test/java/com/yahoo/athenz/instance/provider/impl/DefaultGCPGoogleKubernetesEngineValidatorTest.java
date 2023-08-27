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
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.ResourceException;
import io.jsonwebtoken.SignatureAlgorithm;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.HashMap;

import static com.yahoo.athenz.instance.provider.InstanceProvider.*;
import static com.yahoo.athenz.instance.provider.impl.IdTokenTestsHelper.*;
import static com.yahoo.athenz.instance.provider.impl.IdTokenTestsHelper.removeOpenIdConfigFile;
import static com.yahoo.athenz.instance.provider.impl.InstanceGCPProvider.GCP_PROP_DNS_SUFFIX;
import static com.yahoo.athenz.instance.provider.impl.InstanceGCPProvider.GCP_PROP_GKE_DNS_SUFFIX;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.testng.Assert.*;

public class DefaultGCPGoogleKubernetesEngineValidatorTest {

    private final File ecPrivateKey = new File("./src/test/resources/unit_test_ec_private.key");
    private final File ecPublicKey = new File("./src/test/resources/unit_test_ec_public.key");
    @Test
    public void testInitialize() {
        System.setProperty(GCP_PROP_DNS_SUFFIX, "gcp.athenz.cloud");
        System.setProperty(GCP_PROP_GKE_DNS_SUFFIX, "gke.athenz.cloud");
        DefaultGCPGoogleKubernetesEngineValidator validator = DefaultGCPGoogleKubernetesEngineValidator.getInstance();
        validator.initialize();
        System.clearProperty(GCP_PROP_DNS_SUFFIX);
        System.clearProperty(GCP_PROP_GKE_DNS_SUFFIX);
    }

    @Test
    public void testValidateIssuerNoValidator() {
        DefaultGCPGoogleKubernetesEngineValidator validator = DefaultGCPGoogleKubernetesEngineValidator.getInstance();
        try {
            IdTokenAttestationData attestationData = new IdTokenAttestationData();
            attestationData.setIdentityToken(createToken());
            InstanceConfirmation confirmation = new InstanceConfirmation();
            confirmation.setAttributes(new HashMap<>());
            confirmation.getAttributes().put(InstanceProvider.ZTS_INSTANCE_GCP_PROJECT, "not-my-project");
            String issuer = validator.validateIssuer(confirmation, attestationData, new StringBuilder());
            assertNull(issuer);
        } catch (ResourceException re){
            fail();
        }
    }

    @Test
    public void testValidateIssuerNoIssuerInToken() {
        DefaultGCPGoogleKubernetesEngineValidator validator = DefaultGCPGoogleKubernetesEngineValidator.getInstance();
        try {
            IdToken sampleToken = new IdToken();
            PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
            long now = System.currentTimeMillis() / 1000;
            sampleToken.setExpiryTime(now + 3600);
            sampleToken.setIssueTime(now);
            String testToken = sampleToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
            InstanceConfirmation confirmation = new InstanceConfirmation();
            IdTokenAttestationData attestationData = new IdTokenAttestationData();
            attestationData.setIdentityToken(testToken);
            String issuer = validator.validateIssuer(confirmation, attestationData, new StringBuilder());
            assertNull(issuer);
        } catch (ResourceException re){
            fail();
        }
    }

    @Test
    public void testValidateIssuerOkay() {
        DefaultGCPGoogleKubernetesEngineValidator validator = DefaultGCPGoogleKubernetesEngineValidator.getInstance();
        try {
            String testToken = IdTokenTestsHelper.createToken();
            InstanceConfirmation confirmation = new InstanceConfirmation();
            confirmation.setAttributes(new HashMap<>());
            confirmation.getAttributes().put(InstanceProvider.ZTS_INSTANCE_GCP_PROJECT, "my-project");
            confirmation.getAttributes().put(InstanceProvider.ZTS_INSTANCE_CLOUD, "gcp");
            IdTokenAttestationData attestationData = new IdTokenAttestationData();
            attestationData.setIdentityToken(testToken);
            String issuer = validator.validateIssuer(confirmation, attestationData, new StringBuilder());
            assertEquals(issuer, "https://container.googleapis.com/v1/projects/my-project/zones/us-east1-a/clusters/my-cluster");

        } catch (ResourceException re){
            fail();
        }
    }

    @Test
    public void testGetSigningKeyResolver() throws IOException {
        DefaultGCPGoogleKubernetesEngineValidator validator = DefaultGCPGoogleKubernetesEngineValidator.getInstance();
        File configFile = new File("./src/test/resources/codesigning-openid.json");
        File jwksUri = new File("./src/test/resources/codesigning-jwks.json");
        createOpenIdConfigFile(configFile, jwksUri, true);
        validator.jwtsHelper = Mockito.mock(JwtsHelper.class);
        when(validator.jwtsHelper.extractJwksUri(any(), any())).thenReturn("file://" + jwksUri.getCanonicalPath());
        StringBuilder sb = new StringBuilder();
        assertNotNull(validator.getSigningKeyResolverForIssuer("dummy", sb));
        // second call to retrieve from issuerMap
        assertNotNull(validator.getSigningKeyResolverForIssuer("dummy", sb));
        removeOpenIdConfigFile(configFile, jwksUri);
        validator.jwtsHelper = new JwtsHelper();
    }
    @Test
    public void testGetSigningKeyResolverEmptyJwksUri() throws IOException {
        DefaultGCPGoogleKubernetesEngineValidator validator = DefaultGCPGoogleKubernetesEngineValidator.getInstance();
        validator.issuersMap.clear();
        File configFile = new File("./src/test/resources/codesigning-openid.json");
        File jwksUri = new File("./src/test/resources/codesigning-jwks.json");
        createOpenIdConfigFile(configFile, jwksUri, true);
        validator.jwtsHelper = Mockito.mock(JwtsHelper.class);
        when(validator.jwtsHelper.extractJwksUri(any(), any())).thenReturn("");
        try {
            assertNull(validator.getSigningKeyResolverForIssuer("dummy", new StringBuilder()));
        } catch (ResourceException ex) {
            fail();
        }
        removeOpenIdConfigFile(configFile, jwksUri);
        validator.jwtsHelper = new JwtsHelper();
    }
    @Test
    public void testGetSigningKeyResolverNoPubKeys() throws IOException {
        DefaultGCPGoogleKubernetesEngineValidator validator = DefaultGCPGoogleKubernetesEngineValidator.getInstance();
        validator.issuersMap.clear();
        File configFile = new File("./src/test/resources/codesigning-openid.json");
        File jwksUri = new File("./src/test/resources/codesigning-jwks.json");
        createOpenIdConfigFile(configFile, jwksUri, true);
        validator.jwtsHelper = Mockito.mock(JwtsHelper.class);
        when(validator.jwtsHelper.extractJwksUri(any(), any())).thenReturn("file://" + configFile.getCanonicalPath());
        try {
            assertNull(validator.getSigningKeyResolverForIssuer("dummy", new StringBuilder()));
        } catch(ResourceException re) {
            fail();
        }
        removeOpenIdConfigFile(configFile, jwksUri);
        validator.jwtsHelper = new JwtsHelper();
    }
    @Test
    public void testValidateIdToken() throws IOException {
        DefaultGCPGoogleKubernetesEngineValidator validator = DefaultGCPGoogleKubernetesEngineValidator.getInstance();
        validator.issuersMap.clear();
        File configFile = new File("./src/test/resources/codesigning-openid.json");
        File jwksUri = new File("./src/test/resources/codesigning-jwks.json");
        PublicKey publicKey = Crypto.loadPublicKey(ecPublicKey);
        createOpenIdConfigFileWithKey(configFile, jwksUri, true, (ECPublicKey)publicKey);
        validator.jwtsHelper = Mockito.mock(JwtsHelper.class);
        when(validator.jwtsHelper.extractJwksUri(any(), any())).thenReturn("file://" + jwksUri.getCanonicalPath());

        String testToken = IdTokenTestsHelper.createToken();
        IdTokenAttestationData attestationData = new IdTokenAttestationData();
        attestationData.setIdentityToken(testToken);

        IdToken idToken = validator.validateIdToken("https://container.googleapis.com/v1/projects/my-project/zones/us-east1-a/clusters/my-cluster", attestationData, new StringBuilder());
        assertNotNull(idToken);
        removeOpenIdConfigFile(configFile, jwksUri);
        validator.jwtsHelper = new JwtsHelper();
    }

    @Test
    public void testValidateIdTokenException() throws IOException {
        DefaultGCPGoogleKubernetesEngineValidator validator = DefaultGCPGoogleKubernetesEngineValidator.getInstance();
        validator.issuersMap.clear();
        File configFile = new File("./src/test/resources/codesigning-openid.json");
        File jwksUri = new File("./src/test/resources/codesigning-jwks.json");
        createOpenIdConfigFile(configFile, jwksUri, true);
        validator.jwtsHelper = Mockito.mock(JwtsHelper.class);
        when(validator.jwtsHelper.extractJwksUri(any(), any())).thenReturn("file://" + jwksUri.getCanonicalPath());

        String testToken = IdTokenTestsHelper.createToken();
        IdTokenAttestationData attestationData = new IdTokenAttestationData();
        attestationData.setIdentityToken(testToken);

        IdToken idToken =validator.validateIdToken("https://container.googleapis.com/v1/projects/my-project/zones/us-east1-a/clusters/my-cluster", attestationData, new StringBuilder());
        assertNull(idToken);
        removeOpenIdConfigFile(configFile, jwksUri);
        validator.jwtsHelper = new JwtsHelper();
    }

    @Test
    public void testValidateAttestationDataBadIdToken() throws IOException {
        DefaultGCPGoogleKubernetesEngineValidator validator = DefaultGCPGoogleKubernetesEngineValidator.getInstance();
        validator.issuersMap.clear();
        File configFile = new File("./src/test/resources/codesigning-openid.json");
        File jwksUri = new File("./src/test/resources/codesigning-jwks.json");
        createOpenIdConfigFile(configFile, jwksUri, true);
        validator.jwtsHelper = Mockito.mock(JwtsHelper.class);
        when(validator.jwtsHelper.extractJwksUri(any(), any())).thenReturn("file://" + jwksUri.getCanonicalPath());

        String testToken = IdTokenTestsHelper.createToken();
        IdTokenAttestationData attestationData = new IdTokenAttestationData();
        attestationData.setIdentityToken(testToken);
        InstanceConfirmation confirmation = new InstanceConfirmation();
        assertFalse(validator.validateAttestationData(confirmation,  attestationData, "https://container.googleapis.com/v1/projects/my-project/zones/us-east1-a/clusters/my-cluster", new StringBuilder()));
        removeOpenIdConfigFile(configFile, jwksUri);
        validator.jwtsHelper = new JwtsHelper();
    }

    @Test
    public void testValidateAttestationDataBadAudience() throws IOException {
        DefaultGCPGoogleKubernetesEngineValidator validator = DefaultGCPGoogleKubernetesEngineValidator.getInstance();
        validator.issuersMap.clear();
        validator.initialize();
        File configFile = new File("./src/test/resources/codesigning-openid.json");
        File jwksUri = new File("./src/test/resources/codesigning-jwks.json");
        PublicKey publicKey = Crypto.loadPublicKey(ecPublicKey);
        createOpenIdConfigFileWithKey(configFile, jwksUri, true, (ECPublicKey)publicKey);
        validator.jwtsHelper = Mockito.mock(JwtsHelper.class);
        when(validator.jwtsHelper.extractJwksUri(any(), any())).thenReturn("file://" + jwksUri.getCanonicalPath());

        String testToken = IdTokenTestsHelper.createToken();
        IdTokenAttestationData attestationData = new IdTokenAttestationData();
        attestationData.setIdentityToken(testToken);
        InstanceConfirmation confirmation = new InstanceConfirmation();
        assertFalse(validator.validateAttestationData(confirmation,  attestationData, "https://container.googleapis.com/v1/projects/my-project/zones/us-east1-a/clusters/my-cluster", new StringBuilder()));
        removeOpenIdConfigFile(configFile, jwksUri);
        validator.jwtsHelper = new JwtsHelper();
    }

    @Test
    public void testValidateSubjectNoMatch() {
        DefaultGCPGoogleKubernetesEngineValidator validator = DefaultGCPGoogleKubernetesEngineValidator.getInstance();
        validator.issuersMap.clear();
        validator.initialize();
        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("my-domain");
        confirmation.setService("my-service");
        IdToken idToken = new IdToken();
        idToken.setSubject("athenz.api");
        assertFalse(validator.validateSubject(confirmation, idToken, new StringBuilder()));
    }

    @Test
    public void testValidateSubject() {
        DefaultGCPGoogleKubernetesEngineValidator validator = DefaultGCPGoogleKubernetesEngineValidator.getInstance();
        validator.issuersMap.clear();
        validator.initialize();
        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("my-domain");
        confirmation.setService("my-service");
        IdToken idToken = new IdToken();
        idToken.setSubject("system:serviceaccount:myns:my-domain.my-service");
        assertTrue(validator.validateSubject(confirmation, idToken, new StringBuilder()));
    }

    @Test
    public void testValidateSanDNSEntries() {
        System.setProperty(InstanceGCPProvider.GCP_PROP_DNS_SUFFIX, "gcp.athenz.cloud");
        DefaultGCPGoogleKubernetesEngineValidator validator = DefaultGCPGoogleKubernetesEngineValidator.getInstance();
        validator.initialize();
        InstanceConfirmation instanceConfirmation = new InstanceConfirmation();
        instanceConfirmation.setDomain("my-domain");
        instanceConfirmation.setService("my-service");
        instanceConfirmation.setAttributes(new HashMap<>());
        instanceConfirmation.getAttributes().put(ZTS_INSTANCE_GCP_PROJECT, "my-project");
        instanceConfirmation.getAttributes().put(ZTS_INSTANCE_SAN_DNS, "my-service.my-domain.gcp.athenz.cloud,abs2-ddce-221-32df.instanceid.athenz.gcp.athenz.cloud");
        System.clearProperty(InstanceGCPProvider.GCP_PROP_DNS_SUFFIX);

        assertTrue(validator.validateSanDNSEntries(instanceConfirmation, new StringBuilder()));
    }

    @Test
    public void testValidateSanDNSEntriesNoAccount() {
        System.setProperty(InstanceGCPProvider.GCP_PROP_DNS_SUFFIX, "gcp.athenz.cloud");
        DefaultGCPGoogleKubernetesEngineValidator validator = DefaultGCPGoogleKubernetesEngineValidator.getInstance();
        validator.initialize();
        InstanceConfirmation instanceConfirmation = new InstanceConfirmation();
        instanceConfirmation.setDomain("my-domain");
        instanceConfirmation.setService("my-service");
        instanceConfirmation.setAttributes(new HashMap<>());
        instanceConfirmation.getAttributes().put(ZTS_INSTANCE_SAN_DNS, "my-service.my-domain.gcp.athenz.cloud,abs2-ddce-221-32df.instanceid.athenz.gcp.athenz.cloud");
        System.clearProperty(InstanceGCPProvider.GCP_PROP_DNS_SUFFIX);

        assertFalse(validator.validateSanDNSEntries(instanceConfirmation, new StringBuilder()));
    }

    @Test
    public void testValidateSanDNSEntriesIncorrectEntries() {
        System.setProperty(InstanceGCPProvider.GCP_PROP_DNS_SUFFIX, "gcp.athenz.cloud");
        DefaultGCPGoogleKubernetesEngineValidator validator = DefaultGCPGoogleKubernetesEngineValidator.getInstance();
        validator.initialize();
        InstanceConfirmation instanceConfirmation = new InstanceConfirmation();
        instanceConfirmation.setDomain("my-domain");
        instanceConfirmation.setService("my-service");
        instanceConfirmation.setAttributes(new HashMap<>());
        instanceConfirmation.getAttributes().put(ZTS_INSTANCE_GCP_PROJECT, "my-project");
        instanceConfirmation.getAttributes().put(ZTS_INSTANCE_SAN_DNS, "my-service.my-domain.gcp.athenz.cloud");
        System.clearProperty(InstanceGCPProvider.GCP_PROP_DNS_SUFFIX);

        assertFalse(validator.validateSanDNSEntries(instanceConfirmation, new StringBuilder()));
    }

}