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

import com.yahoo.athenz.auth.impl.aws.AwsPrivateKeyStore;
import org.mockito.MockedStatic;
import software.amazon.awssdk.services.iam.IamClientBuilder;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.iam.model.ListOpenIdConnectProvidersRequest;
import software.amazon.awssdk.services.iam.model.ListOpenIdConnectProvidersResponse;
import software.amazon.awssdk.services.iam.model.OpenIDConnectProviderListEntry;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.services.sts.model.AssumeRoleResponse;

import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigBoolean;
import com.yahoo.athenz.instance.provider.AttrValidator;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import software.amazon.awssdk.services.sts.model.Credentials;

import javax.net.ssl.SSLContext;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;

import static com.yahoo.athenz.instance.provider.InstanceProvider.ZTS_INSTANCE_AWS_ACCOUNT;
import static com.yahoo.athenz.instance.provider.InstanceProvider.ZTS_INSTANCE_SAN_DNS;
import static com.yahoo.athenz.instance.provider.impl.IdTokenTestsHelper.createToken;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
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
        StsClient sts = Mockito.mock(StsClient.class);
        validator.stsClient = sts;
        AssumeRoleResponse assumeRoleResult = Mockito.mock(AssumeRoleResponse.class);
        Credentials creds = Mockito.mock(Credentials.class);
        when(creds.accessKeyId()).thenReturn("abc");
        when(creds.secretAccessKey()).thenReturn("def");
        when(creds.sessionToken()).thenReturn("ghi");
        when(assumeRoleResult.credentials()).thenReturn(creds);
        when(sts.assumeRole(any(AssumeRoleRequest.class))).thenReturn(assumeRoleResult);

        try (MockedStatic<IamClient> iamClientStatic = Mockito.mockStatic(IamClient.class)) {
            IamClientBuilder iamClientBuilder = Mockito.mock(IamClientBuilder.class);

            IamClient iamClient = Mockito.mock(IamClient.class);

            iamClientStatic.when(IamClient::builder).thenReturn(iamClientBuilder);
            when(iamClientBuilder.credentialsProvider(any())).thenReturn(iamClientBuilder);
            when(iamClientBuilder.region(any())).thenReturn(iamClientBuilder);
            when(iamClientBuilder.build()).thenReturn(iamClient);

            List<OpenIDConnectProviderListEntry> providers = List.of(
                    OpenIDConnectProviderListEntry.builder().arn("arn:aws:iam::123456789012:oidc-provider/athenz.provider").build());
            when(iamClient.listOpenIDConnectProviders(any(ListOpenIdConnectProvidersRequest.class)))
                    .thenReturn(ListOpenIdConnectProvidersResponse.builder().openIDConnectProviderList(providers).build());
            assertTrue(validator.verifyIssuerPresenceInDomainAWSAccount("athenz.provider", "123456789012"));
        }
    }

    @Test
    public void testVerifyIssuerPresenceInDomainAWSAccountInvalid() {
        DefaultAWSElasticKubernetesServiceValidator validator = DefaultAWSElasticKubernetesServiceValidator.getInstance();
        StsClient sts = Mockito.mock(StsClient.class);
        validator.stsClient = sts;
        AssumeRoleResponse assumeRoleResult = Mockito.mock(AssumeRoleResponse.class);
        Credentials creds = Mockito.mock(Credentials.class);
        when(creds.accessKeyId()).thenReturn("abc");
        when(creds.secretAccessKey()).thenReturn("def");
        when(creds.sessionToken()).thenReturn("ghi");
        when(assumeRoleResult.credentials()).thenReturn(creds);
        when(sts.assumeRole(any(AssumeRoleRequest.class))).thenReturn(assumeRoleResult);

        try (MockedStatic<IamClient> iamClientStatic = Mockito.mockStatic(IamClient.class)) {
            IamClientBuilder iamClientBuilder = Mockito.mock(IamClientBuilder.class);

            IamClient iamClient = Mockito.mock(IamClient.class);

            iamClientStatic.when(IamClient::builder).thenReturn(iamClientBuilder);
            when(iamClientBuilder.credentialsProvider(any())).thenReturn(iamClientBuilder);
            when(iamClientBuilder.region(any())).thenReturn(iamClientBuilder);
            when(iamClientBuilder.build()).thenReturn(iamClient);

            List<OpenIDConnectProviderListEntry> providers = List.of(
                    OpenIDConnectProviderListEntry.builder().arn("arn:aws:iam::123456789012:oidc-provider/xxx.zzzz").build());
            when(iamClient.listOpenIDConnectProviders(any(ListOpenIdConnectProvidersRequest.class)))
                    .thenReturn(ListOpenIdConnectProvidersResponse.builder().openIDConnectProviderList(providers).build());
            assertFalse(validator.verifyIssuerPresenceInDomainAWSAccount("athenz.provider", "123456789012"));
        }
    }

    @Test
    public void testVerifyIssuerPresenceInDomainAWSAccountNullIssuer() {
        DefaultAWSElasticKubernetesServiceValidator validator = DefaultAWSElasticKubernetesServiceValidator.getInstance();
        StsClient sts = Mockito.mock(StsClient.class);
        validator.stsClient = sts;
        AssumeRoleResponse assumeRoleResult = Mockito.mock(AssumeRoleResponse.class);
        Credentials creds = Mockito.mock(Credentials.class);
        when(creds.accessKeyId()).thenReturn("abc");
        when(creds.secretAccessKey()).thenReturn("def");
        when(creds.sessionToken()).thenReturn("ghi");
        when(assumeRoleResult.credentials()).thenReturn(creds);
        when(sts.assumeRole(any(AssumeRoleRequest.class))).thenReturn(assumeRoleResult);

        try (MockedStatic<IamClient> iamClientStatic = Mockito.mockStatic(IamClient.class)) {
            IamClientBuilder iamClientBuilder = Mockito.mock(IamClientBuilder.class);

            IamClient iamClient = Mockito.mock(IamClient.class);

            iamClientStatic.when(IamClient::builder).thenReturn(iamClientBuilder);
            when(iamClientBuilder.credentialsProvider(any())).thenReturn(iamClientBuilder);
            when(iamClientBuilder.region(any())).thenReturn(iamClientBuilder);
            when(iamClientBuilder.build()).thenReturn(iamClient);

            when(iamClient.listOpenIDConnectProviders(any(ListOpenIdConnectProvidersRequest.class)))
                    .thenReturn(ListOpenIdConnectProvidersResponse.builder()
                            .openIDConnectProviderList((Collection<OpenIDConnectProviderListEntry>) null).build());
            assertFalse(validator.verifyIssuerPresenceInDomainAWSAccount("athenz.provider", "123456789012"));
        }
    }

    @Test
    public void testInit() {
        DefaultAWSElasticKubernetesServiceValidator validator = DefaultAWSElasticKubernetesServiceValidator.getInstance();
        SSLContext sslContext = Mockito.mock(SSLContext.class);
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        validator.initialize(sslContext, authorizer);
        assertNotNull(validator.stsClient);
    }

    @Test
    public void testValidateIssuer() {

        DefaultAWSElasticKubernetesServiceValidator validator = DefaultAWSElasticKubernetesServiceValidator.getInstance();

        SSLContext sslContext = Mockito.mock(SSLContext.class);
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        when(authorizer.access(any(), any(), any(), any())).thenReturn(true);
        validator.initialize(sslContext, authorizer);
        InstanceConfirmation instanceConfirmation = new InstanceConfirmation();
        instanceConfirmation.setAttributes(new HashMap<>());
        IdTokenAttestationData attestationData = new IdTokenAttestationData();
        attestationData.setIdentityToken(createToken("athenz.api", "https://zts.athenz.io/zts/v1",
                "https://oidc.eks.us-east-1.amazonaws.com/id/123456789012"));

        StsClient sts = Mockito.mock(StsClient.class);
        validator.stsClient = sts;
        AssumeRoleResponse assumeRoleResult = Mockito.mock(AssumeRoleResponse.class);
        Credentials creds = Mockito.mock(Credentials.class);
        when(creds.accessKeyId()).thenReturn("abc");
        when(creds.secretAccessKey()).thenReturn("def");
        when(creds.sessionToken()).thenReturn("ghi");
        when(assumeRoleResult.credentials()).thenReturn(creds);
        when(sts.assumeRole(any(AssumeRoleRequest.class))).thenReturn(assumeRoleResult);

        try (MockedStatic<IamClient> iamClientStatic = Mockito.mockStatic(IamClient.class)) {
            IamClientBuilder iamClientBuilder = Mockito.mock(IamClientBuilder.class);

            IamClient iamClient = Mockito.mock(IamClient.class);

            iamClientStatic.when(IamClient::builder).thenReturn(iamClientBuilder);
            when(iamClientBuilder.credentialsProvider(any())).thenReturn(iamClientBuilder);
            when(iamClientBuilder.region(any())).thenReturn(iamClientBuilder);
            when(iamClientBuilder.build()).thenReturn(iamClient);

            List<OpenIDConnectProviderListEntry> providers = List.of(
                    OpenIDConnectProviderListEntry.builder().arn("arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/123456789012").build());
            when(iamClient.listOpenIDConnectProviders(any(ListOpenIdConnectProvidersRequest.class)))
                    .thenReturn(ListOpenIdConnectProvidersResponse.builder().openIDConnectProviderList(providers).build());
            assertEquals(validator.validateIssuer(instanceConfirmation, attestationData,
                    new StringBuilder()), "https://oidc.eks.us-east-1.amazonaws.com/id/123456789012");
        }
    }

    @Test
    public void testValidateIssuerWithoutIAM() {
        DefaultAWSElasticKubernetesServiceValidator validator = DefaultAWSElasticKubernetesServiceValidator.getInstance();
        SSLContext sslContext = Mockito.mock(SSLContext.class);
        System.setProperty(DefaultAWSElasticKubernetesServiceValidator.ZTS_PROP_K8S_PROVIDER_AWS_ATTR_VALIDATOR_FACTORY_CLASS, "com.yahoo.athenz.instance.provider.impl.MockAttrValidatorFactory");
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        when(authorizer.access(any(), any(), any(), any())).thenReturn(true);
        validator.initialize(sslContext, authorizer);
        validator.useIamRoleForIssuerAttestation = new DynamicConfigBoolean(Boolean.FALSE);
        InstanceConfirmation instanceConfirmation = new InstanceConfirmation();
        instanceConfirmation.setAttributes(new HashMap<>());
        IdTokenAttestationData attestationData = new IdTokenAttestationData();
        attestationData.setIdentityToken(createToken("athenz.api", "https://zts.athenz.io/zts/v1", "https://oidc.eks.us-east-1.amazonaws.com/id/123456789012"));
        assertEquals(validator.validateIssuer(instanceConfirmation, attestationData, new StringBuilder()), "https://oidc.eks.us-east-1.amazonaws.com/id/123456789012");
        System.clearProperty(DefaultAWSElasticKubernetesServiceValidator.ZTS_PROP_K8S_PROVIDER_AWS_ATTR_VALIDATOR_FACTORY_CLASS);
    }

    @Test
    public void testValidateIssuerWithoutIAMFail() {
        DefaultAWSElasticKubernetesServiceValidator validator = DefaultAWSElasticKubernetesServiceValidator.getInstance();
        SSLContext sslContext = Mockito.mock(SSLContext.class);
        System.setProperty(DefaultAWSElasticKubernetesServiceValidator.ZTS_PROP_K8S_PROVIDER_AWS_ATTR_VALIDATOR_FACTORY_CLASS, "com.yahoo.athenz.instance.provider.impl.MockFailingAttrValidatorFactory");
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        validator.initialize(sslContext, authorizer);
        validator.useIamRoleForIssuerAttestation = new DynamicConfigBoolean(Boolean.FALSE);
        InstanceConfirmation instanceConfirmation = new InstanceConfirmation();
        instanceConfirmation.setAttributes(new HashMap<>());
        IdTokenAttestationData attestationData = new IdTokenAttestationData();
        attestationData.setIdentityToken(createToken("athenz.api", "https://zts.athenz.io/zts/v1", "https://oidc.eks.us-east-1.amazonaws.com/id/123456789012"));
        assertNull(validator.validateIssuer(instanceConfirmation, attestationData, new StringBuilder()));
        System.clearProperty(DefaultAWSElasticKubernetesServiceValidator.ZTS_PROP_K8S_PROVIDER_AWS_ATTR_VALIDATOR_FACTORY_CLASS);
    }

    @Test
    public void testValidateIssuerNoLaunchAuthorization() {
        DefaultAWSElasticKubernetesServiceValidator validator = DefaultAWSElasticKubernetesServiceValidator.getInstance();
        SSLContext sslContext = Mockito.mock(SSLContext.class);
        System.setProperty(DefaultAWSElasticKubernetesServiceValidator.ZTS_PROP_K8S_PROVIDER_AWS_ATTR_VALIDATOR_FACTORY_CLASS, "com.yahoo.athenz.instance.provider.impl.MockAttrValidatorFactory");
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        when(authorizer.access(any(), any(), any(), any())).thenReturn(false);
        validator.initialize(sslContext, authorizer);
        validator.useIamRoleForIssuerAttestation = new DynamicConfigBoolean(Boolean.FALSE);
        InstanceConfirmation instanceConfirmation = new InstanceConfirmation();
        instanceConfirmation.setAttributes(new HashMap<>());
        IdTokenAttestationData attestationData = new IdTokenAttestationData();
        attestationData.setIdentityToken(createToken("athenz.api", "https://zts.athenz.io/zts/v1", "https://oidc.eks.us-east-1.amazonaws.com/id/123456789012"));
        assertNull(validator.validateIssuer(instanceConfirmation, attestationData, new StringBuilder()));
        System.clearProperty(DefaultAWSElasticKubernetesServiceValidator.ZTS_PROP_K8S_PROVIDER_AWS_ATTR_VALIDATOR_FACTORY_CLASS);
    }

    @Test
    public void testValidateIssuerNoIssuerInToken() {
        DefaultAWSElasticKubernetesServiceValidator validator = DefaultAWSElasticKubernetesServiceValidator.getInstance();
        SSLContext sslContext = Mockito.mock(SSLContext.class);
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        validator.initialize(sslContext, authorizer);
        InstanceConfirmation instanceConfirmation = new InstanceConfirmation();
        instanceConfirmation.setAttributes(new HashMap<>());
        IdTokenAttestationData attestationData = new IdTokenAttestationData();
        attestationData.setIdentityToken(createToken("athenz.api", "https://zts.athenz.io/zts/v1", null));

        assertNull(validator.validateIssuer(instanceConfirmation, attestationData, new StringBuilder()));
    }

    @Test
    public void testValidateIssuerNullIssuerDomain() {
        DefaultAWSElasticKubernetesServiceValidator validator = DefaultAWSElasticKubernetesServiceValidator.getInstance();
        SSLContext sslContext = Mockito.mock(SSLContext.class);
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        validator.initialize(sslContext, authorizer);
        InstanceConfirmation instanceConfirmation = new InstanceConfirmation();
        instanceConfirmation.setAttributes(new HashMap<>());
        IdTokenAttestationData attestationData = new IdTokenAttestationData();
        attestationData.setIdentityToken(createToken("athenz.api", "https://zts.athenz.io/zts/v1", "invalid"));

        assertNull(validator.validateIssuer(instanceConfirmation, attestationData, new StringBuilder()));
    }

    @Test
    public void testValidateIssuerNullInvalidIssuerDomain() {
        DefaultAWSElasticKubernetesServiceValidator validator = DefaultAWSElasticKubernetesServiceValidator.getInstance();
        SSLContext sslContext = Mockito.mock(SSLContext.class);
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        validator.initialize(sslContext, authorizer);
        InstanceConfirmation instanceConfirmation = new InstanceConfirmation();
        instanceConfirmation.setAttributes(new HashMap<>());
        IdTokenAttestationData attestationData = new IdTokenAttestationData();
        attestationData.setIdentityToken(createToken("athenz.api", "https://zts.athenz.io/zts/v1", "https://abc.com/invalid"));
        assertNull(validator.validateIssuer(instanceConfirmation, attestationData, new StringBuilder()));
    }

    @Test
    public void testValidateIssuerNoIssuerMatch() {
        DefaultAWSElasticKubernetesServiceValidator validator = DefaultAWSElasticKubernetesServiceValidator.getInstance();
        SSLContext sslContext = Mockito.mock(SSLContext.class);
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        validator.initialize(sslContext, authorizer);
        InstanceConfirmation instanceConfirmation = new InstanceConfirmation();
        instanceConfirmation.setAttributes(new HashMap<>());
        IdTokenAttestationData attestationData = new IdTokenAttestationData();
        attestationData.setIdentityToken(createToken("athenz.api", "https://zts.athenz.io/zts/v1", "https://oidc.eks.us-east-1.amazonaws.com/id/123456789012"));

        StsClient sts = Mockito.mock(StsClient.class);
        validator.stsClient = sts;
        AssumeRoleResponse assumeRoleResult = Mockito.mock(AssumeRoleResponse.class);
        Credentials creds = Mockito.mock(Credentials.class);
        when(creds.accessKeyId()).thenReturn("abc");
        when(creds.secretAccessKey()).thenReturn("def");
        when(creds.sessionToken()).thenReturn("ghi");
        when(assumeRoleResult.credentials()).thenReturn(creds);
        when(sts.assumeRole(any(AssumeRoleRequest.class))).thenReturn(assumeRoleResult);

        try (MockedStatic<IamClient> iamClientStatic = Mockito.mockStatic(IamClient.class)) {
            IamClientBuilder iamClientBuilder = Mockito.mock(IamClientBuilder.class);

            IamClient iamClient = Mockito.mock(IamClient.class);

            iamClientStatic.when(IamClient::builder).thenReturn(iamClientBuilder);
            when(iamClientBuilder.credentialsProvider(any())).thenReturn(iamClientBuilder);
            when(iamClientBuilder.region(any())).thenReturn(iamClientBuilder);
            when(iamClientBuilder.build()).thenReturn(iamClient);

            List<OpenIDConnectProviderListEntry> providers = List.of(
                    OpenIDConnectProviderListEntry.builder().arn("arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/999999999999").build());
            when(iamClient.listOpenIDConnectProviders(any(ListOpenIdConnectProvidersRequest.class)))
                    .thenReturn(ListOpenIdConnectProvidersResponse.builder().openIDConnectProviderList(providers).build());
            assertNull(validator.validateIssuer(instanceConfirmation, attestationData, new StringBuilder()));
        }
    }

    @Test
    public void testValidateSanDNSEntries() {
        System.setProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX, "aws.athenz.cloud");
        DefaultAWSElasticKubernetesServiceValidator validator = DefaultAWSElasticKubernetesServiceValidator.getInstance();
        SSLContext sslContext = Mockito.mock(SSLContext.class);
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        validator.initialize(sslContext, authorizer);
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
        SSLContext sslContext = Mockito.mock(SSLContext.class);
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        validator.initialize(sslContext, authorizer);
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
        SSLContext sslContext = Mockito.mock(SSLContext.class);
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        validator.initialize(sslContext, authorizer);
        InstanceConfirmation instanceConfirmation = new InstanceConfirmation();
        instanceConfirmation.setDomain("my-domain");
        instanceConfirmation.setService("my-service");
        instanceConfirmation.setAttributes(new HashMap<>());
        instanceConfirmation.getAttributes().put(ZTS_INSTANCE_AWS_ACCOUNT, "123456789012");
        instanceConfirmation.getAttributes().put(ZTS_INSTANCE_SAN_DNS, "my-service.my-domain.aws.athenz.cloud");
        System.clearProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX);

        assertFalse(validator.validateSanDNSEntries(instanceConfirmation, new StringBuilder()));
    }

    @Test
    public void testNewAttrValidator() {
        System.setProperty(DefaultAWSElasticKubernetesServiceValidator.ZTS_PROP_K8S_PROVIDER_AWS_ATTR_VALIDATOR_FACTORY_CLASS, "com.yahoo.athenz.instance.provider.impl.MockAttrValidatorFactory");
        AttrValidator attrValidator = DefaultAWSElasticKubernetesServiceValidator.newAttrValidator(null);
        assertNotNull(attrValidator);
        assertTrue(attrValidator.confirm(null));
        System.clearProperty(DefaultAWSElasticKubernetesServiceValidator.ZTS_PROP_K8S_PROVIDER_AWS_ATTR_VALIDATOR_FACTORY_CLASS);
    }

    @Test
    public void testNewAttrValidatorFail() {
        System.setProperty(DefaultAWSElasticKubernetesServiceValidator.ZTS_PROP_K8S_PROVIDER_AWS_ATTR_VALIDATOR_FACTORY_CLASS, "NoClass");
        try {
            DefaultAWSElasticKubernetesServiceValidator.newAttrValidator(null);
            fail();
        } catch (Exception ignored) {
        }
        finally {
            System.clearProperty(DefaultAWSElasticKubernetesServiceValidator.ZTS_PROP_K8S_PROVIDER_AWS_ATTR_VALIDATOR_FACTORY_CLASS);
        }
    }

}
