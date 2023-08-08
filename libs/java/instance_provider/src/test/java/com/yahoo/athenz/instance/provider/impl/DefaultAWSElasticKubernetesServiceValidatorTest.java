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

import com.amazonaws.services.identitymanagement.AmazonIdentityManagement;
import com.amazonaws.services.identitymanagement.AmazonIdentityManagementClientBuilder;
import com.amazonaws.services.identitymanagement.model.ListOpenIDConnectProvidersRequest;
import com.amazonaws.services.identitymanagement.model.ListOpenIDConnectProvidersResult;
import com.amazonaws.services.identitymanagement.model.OpenIDConnectProviderListEntry;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.model.AssumeRoleRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleResult;
import com.amazonaws.services.securitytoken.model.Credentials;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;

import static com.yahoo.athenz.instance.provider.InstanceProvider.ZTS_INSTANCE_AWS_ACCOUNT;
import static com.yahoo.athenz.instance.provider.InstanceProvider.ZTS_INSTANCE_SAN_DNS;
import static com.yahoo.athenz.instance.provider.impl.IdTokenTestsHelper.createToken;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.testng.Assert.*;
import static org.testng.Assert.assertFalse;

public class DefaultAWSElasticKubernetesServiceValidatorTest {

    @BeforeMethod
    public void setup() {
        System.setProperty(InstanceAWSProvider.AWS_PROP_REGION_NAME, "us-west-2");
    }

    @AfterMethod
    public void shutdown() {
        System.clearProperty(InstanceAWSProvider.AWS_PROP_REGION_NAME);
    }
    @Test
    public void testVerifyIssuerPresenceInDomainAWSAccount() {
        DefaultAWSElasticKubernetesServiceValidator validator = DefaultAWSElasticKubernetesServiceValidator.getInstance();
        AWSSecurityTokenService sts = Mockito.mock(AWSSecurityTokenService.class);
        validator.stsClient = sts;
        AssumeRoleResult assumeRoleResult = Mockito.mock(AssumeRoleResult.class);
        Credentials creds = Mockito.mock(Credentials.class);
        when(creds.getAccessKeyId()).thenReturn("abc");
        when(creds.getSecretAccessKey()).thenReturn("def");
        when(creds.getSessionToken()).thenReturn("ghi");
        when(assumeRoleResult.getCredentials()).thenReturn(creds);
        when(sts.assumeRole(any(AssumeRoleRequest.class))).thenReturn(assumeRoleResult);

        try (MockedStatic<AmazonIdentityManagementClientBuilder> iamClientBuilderStatic = Mockito.mockStatic(AmazonIdentityManagementClientBuilder.class)) {
            AmazonIdentityManagementClientBuilder iamClientBuilder = Mockito.mock(AmazonIdentityManagementClientBuilder.class);
            AmazonIdentityManagement iamClient = Mockito.mock(AmazonIdentityManagement.class);

            iamClientBuilderStatic.when(AmazonIdentityManagementClientBuilder::standard).thenReturn(iamClientBuilder);
            when(iamClientBuilder.withCredentials(any())).thenReturn(iamClientBuilder);
            when(iamClientBuilder.withRegion(Mockito.anyString())).thenReturn(iamClientBuilder);
            when(iamClientBuilder.build()).thenReturn(iamClient);
            List<OpenIDConnectProviderListEntry> providers = List.of(new OpenIDConnectProviderListEntry().withArn("arn:aws:iam::123456789012:oidc-provider/athenz.provider"));
            when(iamClient.listOpenIDConnectProviders(any(ListOpenIDConnectProvidersRequest.class))).thenReturn(new ListOpenIDConnectProvidersResult().withOpenIDConnectProviderList(providers));
            assertTrue(validator.verifyIssuerPresenceInDomainAWSAccount( "athenz.provider", "123456789012"));
        }
    }

    @Test
    public void testVerifyIssuerPresenceInDomainAWSAccountInvalid() {
        DefaultAWSElasticKubernetesServiceValidator validator = DefaultAWSElasticKubernetesServiceValidator.getInstance();
        AWSSecurityTokenService sts = Mockito.mock(AWSSecurityTokenService.class);
        validator.stsClient = sts;
        AssumeRoleResult assumeRoleResult = Mockito.mock(AssumeRoleResult.class);
        Credentials creds = Mockito.mock(Credentials.class);
        when(creds.getAccessKeyId()).thenReturn("abc");
        when(creds.getSecretAccessKey()).thenReturn("def");
        when(creds.getSessionToken()).thenReturn("ghi");
        when(assumeRoleResult.getCredentials()).thenReturn(creds);
        when(sts.assumeRole(any(AssumeRoleRequest.class))).thenReturn(assumeRoleResult);

        try (MockedStatic<AmazonIdentityManagementClientBuilder> iamClientBuilderStatic = Mockito.mockStatic(AmazonIdentityManagementClientBuilder.class)) {
            AmazonIdentityManagementClientBuilder iamClientBuilder = Mockito.mock(AmazonIdentityManagementClientBuilder.class);
            AmazonIdentityManagement iamClient = Mockito.mock(AmazonIdentityManagement.class);

            iamClientBuilderStatic.when(AmazonIdentityManagementClientBuilder::standard).thenReturn(iamClientBuilder);
            when(iamClientBuilder.withCredentials(any())).thenReturn(iamClientBuilder);
            when(iamClientBuilder.withRegion(Mockito.anyString())).thenReturn(iamClientBuilder);
            when(iamClientBuilder.build()).thenReturn(iamClient);
            List<OpenIDConnectProviderListEntry> providers = List.of(new OpenIDConnectProviderListEntry().withArn("arn:aws:iam::123456789012:oidc-provider/xxx.zzzz"));
            when(iamClient.listOpenIDConnectProviders(any(ListOpenIDConnectProvidersRequest.class))).thenReturn(new ListOpenIDConnectProvidersResult().withOpenIDConnectProviderList(providers));
            assertFalse(validator.verifyIssuerPresenceInDomainAWSAccount("athenz.provider", "123456789012"));
        }
    }

    @Test
    public void testVerifyIssuerPresenceInDomainAWSAccountNullIssuer() {
        DefaultAWSElasticKubernetesServiceValidator validator = DefaultAWSElasticKubernetesServiceValidator.getInstance();
        AWSSecurityTokenService sts = Mockito.mock(AWSSecurityTokenService.class);
        validator.stsClient = sts;
        AssumeRoleResult assumeRoleResult = Mockito.mock(AssumeRoleResult.class);
        Credentials creds = Mockito.mock(Credentials.class);
        when(creds.getAccessKeyId()).thenReturn("abc");
        when(creds.getSecretAccessKey()).thenReturn("def");
        when(creds.getSessionToken()).thenReturn("ghi");
        when(assumeRoleResult.getCredentials()).thenReturn(creds);
        when(sts.assumeRole(any(AssumeRoleRequest.class))).thenReturn(assumeRoleResult);

        try (MockedStatic<AmazonIdentityManagementClientBuilder> iamClientBuilderStatic = Mockito.mockStatic(AmazonIdentityManagementClientBuilder.class)) {
            AmazonIdentityManagementClientBuilder iamClientBuilder = Mockito.mock(AmazonIdentityManagementClientBuilder.class);
            AmazonIdentityManagement iamClient = Mockito.mock(AmazonIdentityManagement.class);

            iamClientBuilderStatic.when(AmazonIdentityManagementClientBuilder::standard).thenReturn(iamClientBuilder);
            when(iamClientBuilder.withCredentials(any())).thenReturn(iamClientBuilder);
            when(iamClientBuilder.withRegion(Mockito.anyString())).thenReturn(iamClientBuilder);
            when(iamClientBuilder.build()).thenReturn(iamClient);
            when(iamClient.listOpenIDConnectProviders(any(ListOpenIDConnectProvidersRequest.class))).thenReturn(new ListOpenIDConnectProvidersResult().withOpenIDConnectProviderList((Collection<OpenIDConnectProviderListEntry>) null));
            assertFalse(validator.verifyIssuerPresenceInDomainAWSAccount( "athenz.provider", "123456789012"));
        }
    }
    @Test
    public void testInit() {
        DefaultAWSElasticKubernetesServiceValidator validator = DefaultAWSElasticKubernetesServiceValidator.getInstance();
        validator.initialize();
        assertNotNull(validator.stsClient);
    }

    @Test
    public void testValidateIssuer() {
        DefaultAWSElasticKubernetesServiceValidator validator = DefaultAWSElasticKubernetesServiceValidator.getInstance();
        validator.initialize();
        InstanceConfirmation instanceConfirmation = new InstanceConfirmation();
        instanceConfirmation.setAttributes(new HashMap<>());
        IdTokenAttestationData attestationData = new IdTokenAttestationData();
        attestationData.setIdentityToken(createToken("athenz.api", "https://zts.athenz.io/zts/v1", "https://oidc.eks.us-east-1.amazonaws.com/id/123456789012"));
        AWSSecurityTokenService sts = Mockito.mock(AWSSecurityTokenService.class);
        validator.stsClient = sts;
        AssumeRoleResult assumeRoleResult = Mockito.mock(AssumeRoleResult.class);
        Credentials creds = Mockito.mock(Credentials.class);
        when(creds.getAccessKeyId()).thenReturn("abc");
        when(creds.getSecretAccessKey()).thenReturn("def");
        when(creds.getSessionToken()).thenReturn("ghi");
        when(assumeRoleResult.getCredentials()).thenReturn(creds);
        when(sts.assumeRole(any(AssumeRoleRequest.class))).thenReturn(assumeRoleResult);

        try (MockedStatic<AmazonIdentityManagementClientBuilder> iamClientBuilderStatic = Mockito.mockStatic(AmazonIdentityManagementClientBuilder.class)) {
            AmazonIdentityManagementClientBuilder iamClientBuilder = Mockito.mock(AmazonIdentityManagementClientBuilder.class);
            AmazonIdentityManagement iamClient = Mockito.mock(AmazonIdentityManagement.class);

            iamClientBuilderStatic.when(AmazonIdentityManagementClientBuilder::standard).thenReturn(iamClientBuilder);
            when(iamClientBuilder.withCredentials(any())).thenReturn(iamClientBuilder);
            when(iamClientBuilder.withRegion(Mockito.anyString())).thenReturn(iamClientBuilder);
            when(iamClientBuilder.build()).thenReturn(iamClient);
            List<OpenIDConnectProviderListEntry> providers = List.of(new OpenIDConnectProviderListEntry().withArn("arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/123456789012"));
            when(iamClient.listOpenIDConnectProviders(any(ListOpenIDConnectProvidersRequest.class))).thenReturn(new ListOpenIDConnectProvidersResult().withOpenIDConnectProviderList(providers));
            assertEquals(validator.validateIssuer(instanceConfirmation, attestationData, new StringBuilder()), "https://oidc.eks.us-east-1.amazonaws.com/id/123456789012");
        }
    }

    @Test
    public void testValidateIssuerNoIssuerInToken() {
        DefaultAWSElasticKubernetesServiceValidator validator = DefaultAWSElasticKubernetesServiceValidator.getInstance();
        validator.initialize();
        InstanceConfirmation instanceConfirmation = new InstanceConfirmation();
        instanceConfirmation.setAttributes(new HashMap<>());
        IdTokenAttestationData attestationData = new IdTokenAttestationData();
        attestationData.setIdentityToken(createToken("athenz.api", "https://zts.athenz.io/zts/v1", null));

        assertNull(validator.validateIssuer(instanceConfirmation, attestationData, new StringBuilder()));
    }
    @Test
    public void testValidateIssuerNullIssuerDomain() {
        DefaultAWSElasticKubernetesServiceValidator validator = DefaultAWSElasticKubernetesServiceValidator.getInstance();
        validator.initialize();
        InstanceConfirmation instanceConfirmation = new InstanceConfirmation();
        instanceConfirmation.setAttributes(new HashMap<>());
        IdTokenAttestationData attestationData = new IdTokenAttestationData();
        attestationData.setIdentityToken(createToken("athenz.api", "https://zts.athenz.io/zts/v1", "invalid"));

        assertNull(validator.validateIssuer(instanceConfirmation, attestationData, new StringBuilder()));
    }

    @Test
    public void testValidateIssuerNullInvalidIssuerDomain() {
        DefaultAWSElasticKubernetesServiceValidator validator = DefaultAWSElasticKubernetesServiceValidator.getInstance();
        validator.initialize();
        InstanceConfirmation instanceConfirmation = new InstanceConfirmation();
        instanceConfirmation.setAttributes(new HashMap<>());
        IdTokenAttestationData attestationData = new IdTokenAttestationData();
        attestationData.setIdentityToken(createToken("athenz.api", "https://zts.athenz.io/zts/v1", "https://abc.com/invalid"));
        assertNull(validator.validateIssuer(instanceConfirmation, attestationData, new StringBuilder()));
    }

    @Test
    public void testValidateIssuerNoIssuerMatch() {
        DefaultAWSElasticKubernetesServiceValidator validator = DefaultAWSElasticKubernetesServiceValidator.getInstance();
        validator.initialize();
        InstanceConfirmation instanceConfirmation = new InstanceConfirmation();
        instanceConfirmation.setAttributes(new HashMap<>());
        IdTokenAttestationData attestationData = new IdTokenAttestationData();
        attestationData.setIdentityToken(createToken("athenz.api", "https://zts.athenz.io/zts/v1", "https://oidc.eks.us-east-1.amazonaws.com/id/123456789012"));

        AWSSecurityTokenService sts = Mockito.mock(AWSSecurityTokenService.class);
        validator.stsClient = sts;
        AssumeRoleResult assumeRoleResult = Mockito.mock(AssumeRoleResult.class);
        Credentials creds = Mockito.mock(Credentials.class);
        when(creds.getAccessKeyId()).thenReturn("abc");
        when(creds.getSecretAccessKey()).thenReturn("def");
        when(creds.getSessionToken()).thenReturn("ghi");
        when(assumeRoleResult.getCredentials()).thenReturn(creds);
        when(sts.assumeRole(any(AssumeRoleRequest.class))).thenReturn(assumeRoleResult);

        try (MockedStatic<AmazonIdentityManagementClientBuilder> iamClientBuilderStatic = Mockito.mockStatic(AmazonIdentityManagementClientBuilder.class)) {
            AmazonIdentityManagementClientBuilder iamClientBuilder = Mockito.mock(AmazonIdentityManagementClientBuilder.class);
            AmazonIdentityManagement iamClient = Mockito.mock(AmazonIdentityManagement.class);

            iamClientBuilderStatic.when(AmazonIdentityManagementClientBuilder::standard).thenReturn(iamClientBuilder);
            when(iamClientBuilder.withCredentials(any())).thenReturn(iamClientBuilder);
            when(iamClientBuilder.withRegion(Mockito.anyString())).thenReturn(iamClientBuilder);
            when(iamClientBuilder.build()).thenReturn(iamClient);
            List<OpenIDConnectProviderListEntry> providers = List.of(new OpenIDConnectProviderListEntry().withArn("arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/999999999999"));
            when(iamClient.listOpenIDConnectProviders(any(ListOpenIDConnectProvidersRequest.class))).thenReturn(new ListOpenIDConnectProvidersResult().withOpenIDConnectProviderList(providers));
            assertNull(validator.validateIssuer(instanceConfirmation, attestationData, new StringBuilder()));
        }
    }

    @Test
    public void testValidateSanDNSEntries() {
        System.setProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX, "aws.athenz.cloud");
        DefaultAWSElasticKubernetesServiceValidator validator = DefaultAWSElasticKubernetesServiceValidator.getInstance();
        validator.initialize();
        InstanceConfirmation instanceConfirmation = new InstanceConfirmation();
        instanceConfirmation.setDomain("my-domain");
        instanceConfirmation.setService("my-service");
        instanceConfirmation.setAttributes(new HashMap<>());
        instanceConfirmation.getAttributes().put(ZTS_INSTANCE_AWS_ACCOUNT, "123456789012");
        instanceConfirmation.getAttributes().put(ZTS_INSTANCE_SAN_DNS, "my-service.my-domain.aws.athenz.cloud,abs2-ddce-221-32df.instanceid.athenz.aws.athenz.cloud");
        System.clearProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX);

        assertTrue(validator.validateSanDNSEntries(instanceConfirmation, new StringBuilder()));
    }

    @Test
    public void testValidateSanDNSEntriesNoAccount() {
        System.setProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX, "aws.athenz.cloud");
        DefaultAWSElasticKubernetesServiceValidator validator = DefaultAWSElasticKubernetesServiceValidator.getInstance();
        validator.initialize();
        InstanceConfirmation instanceConfirmation = new InstanceConfirmation();
        instanceConfirmation.setDomain("my-domain");
        instanceConfirmation.setService("my-service");
        instanceConfirmation.setAttributes(new HashMap<>());
        instanceConfirmation.getAttributes().put(ZTS_INSTANCE_SAN_DNS, "my-service.my-domain.aws.athenz.cloud,abs2-ddce-221-32df.instanceid.athenz.aws.athenz.cloud");
        System.clearProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX);

        assertFalse(validator.validateSanDNSEntries(instanceConfirmation, new StringBuilder()));
    }

    @Test
    public void testValidateSanDNSEntriesIncorrectEntries() {
        System.setProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX, "aws.athenz.cloud");
        DefaultAWSElasticKubernetesServiceValidator validator = DefaultAWSElasticKubernetesServiceValidator.getInstance();
        validator.initialize();
        InstanceConfirmation instanceConfirmation = new InstanceConfirmation();
        instanceConfirmation.setDomain("my-domain");
        instanceConfirmation.setService("my-service");
        instanceConfirmation.setAttributes(new HashMap<>());
        instanceConfirmation.getAttributes().put(ZTS_INSTANCE_AWS_ACCOUNT, "123456789012");
        instanceConfirmation.getAttributes().put(ZTS_INSTANCE_SAN_DNS, "my-service.my-domain.aws.athenz.cloud");
        System.clearProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX);

        assertFalse(validator.validateSanDNSEntries(instanceConfirmation, new StringBuilder()));
    }
}
