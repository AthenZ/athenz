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

import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.ResourceException;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.Test;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.IamClientBuilder;
import software.amazon.awssdk.services.iam.model.ListOpenIdConnectProvidersRequest;
import software.amazon.awssdk.services.iam.model.ListOpenIdConnectProvidersResponse;
import software.amazon.awssdk.services.iam.model.OpenIDConnectProviderListEntry;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.services.sts.model.AssumeRoleResponse;
import software.amazon.awssdk.services.sts.model.Credentials;

import java.io.File;
import java.io.IOException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;

import static com.yahoo.athenz.instance.provider.InstanceProvider.ZTS_INSTANCE_SAN_DNS;
import static com.yahoo.athenz.instance.provider.impl.CommonKubernetesDistributionValidator.ZTS_PROP_K8S_ATTESTATION_EXPECTED_AUDIENCE;
import static com.yahoo.athenz.instance.provider.impl.IdTokenTestsHelper.*;
import static com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider.AWS_PROP_REGION_NAME;
import static com.yahoo.athenz.instance.provider.impl.InstanceK8SProvider.ZTS_PROP_K8S_PROVIDER_DISTRIBUTION_VALIDATOR_FACTORY_CLASS;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.testng.Assert.*;

public class InstanceK8SProviderTest {

    private static final File ecPublicKey = new File("./src/test/resources/unit_test_ec_public.key");

    @Test
    public void testInitializeDefaults() {
        InstanceK8SProvider provider = new InstanceK8SProvider();
        provider.initialize("k8sprovider", "com.yahoo.athenz.instance.provider.impl.InstanceK8SProvider", null, null);
        assertEquals(provider.getProviderScheme(), InstanceProvider.Scheme.CLASS);
        provider.close();
    }

    @Test
    public void testInitializeNullValues() {
        InstanceK8SProvider provider = new InstanceK8SProvider();
        System.setProperty(ZTS_PROP_K8S_PROVIDER_DISTRIBUTION_VALIDATOR_FACTORY_CLASS,
                "com.yahoo.athenz.instance.provider.impl.MockKubernetesDistributionValidatorFactory");
        try {
            provider.initialize("k8sprovider", "com.yahoo.athenz.instance.provider.impl.InstanceK8SProvider", null, null);
        }catch(Exception ex) {
            fail();
        }
        System.clearProperty(ZTS_PROP_K8S_PROVIDER_DISTRIBUTION_VALIDATOR_FACTORY_CLASS);
        provider.close();
    }

    @Test
    public void testNewOIDCIssuerValidatorFactoryException() {
        InstanceK8SProvider provider = new InstanceK8SProvider();
        System.setProperty(ZTS_PROP_K8S_PROVIDER_DISTRIBUTION_VALIDATOR_FACTORY_CLASS,
                "com.yahoo.athenz.instance.provider.impl.invalid");
        try {
            provider.newKubernetesDistributionValidatorFactory();
            fail();
        } catch(Exception ignored) {
        }
        provider.close();
        System.clearProperty(ZTS_PROP_K8S_PROVIDER_DISTRIBUTION_VALIDATOR_FACTORY_CLASS);
    }

    @Test
    public void testError() {
        InstanceK8SProvider provider = new InstanceK8SProvider();
        ResourceException re = provider.error("error");
        assertEquals(re.getCode(), 403);
        provider.close();
    }

    @Test
    public void testRefreshInstance() {
        InstanceK8SProvider provider = new InstanceK8SProvider();
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
    public void testConfirmInstanceHappyPathGCP() throws IOException {
        File configFile = new File("./src/test/resources/codesigning-openid.json");
        File jwksUri = new File("./src/test/resources/codesigning-jwks.json");
        PublicKey publicKey = Crypto.loadPublicKey(ecPublicKey);
        createOpenIdConfigFileWithKey(configFile, jwksUri, true, (ECPublicKey)publicKey);
        System.setProperty(InstanceGCPProvider.GCP_PROP_DNS_SUFFIX, "gcp.athenz.cloud");
        System.setProperty(ZTS_PROP_K8S_PROVIDER_DISTRIBUTION_VALIDATOR_FACTORY_CLASS,
                "com.yahoo.athenz.instance.provider.impl.DefaultKubernetesDistributionValidatorFactory");
        System.setProperty(AWS_PROP_REGION_NAME, "us-west-2");
        System.setProperty(ZTS_PROP_K8S_ATTESTATION_EXPECTED_AUDIENCE, "https://zts.athenz.io/zts/v1");
        InstanceK8SProvider provider = new InstanceK8SProvider();
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        when(authorizer.access(any(), any(), any(), any())).thenReturn(true);
        provider.setAuthorizer(authorizer);
        provider.initialize("k8sprovider", "com.yahoo.athenz.instance.provider.impl.InstanceK8SProvider", null, null);

        DefaultGCPGoogleKubernetesEngineValidator.getInstance().jwtsHelper = Mockito.mock(JwtsHelper.class);
        when(DefaultGCPGoogleKubernetesEngineValidator.getInstance().jwtsHelper.extractJwksUri(any(), any()))
                .thenReturn("file://" + jwksUri.getCanonicalPath());

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("my-domain");
        confirmation.setService("my-service");
        confirmation.setAttributes(new HashMap<>());
        confirmation.getAttributes().put(InstanceProvider.ZTS_INSTANCE_CLOUD, "gcp");
        confirmation.getAttributes().put(InstanceProvider.ZTS_INSTANCE_GCP_PROJECT, "my-project");
        confirmation.getAttributes().put(ZTS_INSTANCE_SAN_DNS, "my-service.my-domain.gcp.athenz.cloud,abs2-ddce-221-32df.instanceid.athenz.gcp.athenz.cloud");
        confirmation.setAttestationData("{\"identityToken\": \"" + createToken("system:serviceaccount:default:my-domain.my-service",
                "https://zts.athenz.io/zts/v1", "https://container.googleapis.com/v1/projects/my-project/zones/us-east1-a/clusters/my-cluster") +  "\"}");
        try {
            provider.confirmInstance(confirmation);
            assertEquals(confirmation.getAttributes().size(), 2);
            assertEquals(confirmation.getAttributes().get(InstanceProvider.ZTS_CERT_REFRESH), "false");
            assertEquals(confirmation.getAttributes().get(InstanceProvider.ZTS_CERT_EXPIRY_TIME), "10080");
        } catch (ResourceException re) {
            fail();
        }
        provider.close();
        System.clearProperty(ZTS_PROP_K8S_PROVIDER_DISTRIBUTION_VALIDATOR_FACTORY_CLASS);
        System.clearProperty(AWS_PROP_REGION_NAME);
        System.clearProperty(ZTS_PROP_K8S_ATTESTATION_EXPECTED_AUDIENCE);
        System.clearProperty(InstanceGCPProvider.GCP_PROP_DNS_SUFFIX);
        DefaultGCPGoogleKubernetesEngineValidator.getInstance().jwtsHelper = new JwtsHelper();
        removeOpenIdConfigFile(configFile, jwksUri);
    }

    @Test
    public void testConfirmInstanceHappyPathAWS() throws IOException {
        File configFile = new File("./src/test/resources/codesigning-openid.json");
        File jwksUri = new File("./src/test/resources/codesigning-jwks.json");
        PublicKey publicKey = Crypto.loadPublicKey(ecPublicKey);
        createOpenIdConfigFileWithKey(configFile, jwksUri, true, (ECPublicKey)publicKey);
        System.setProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX, "aws.athenz.cloud");
        System.setProperty(ZTS_PROP_K8S_PROVIDER_DISTRIBUTION_VALIDATOR_FACTORY_CLASS,
                "com.yahoo.athenz.instance.provider.impl.DefaultKubernetesDistributionValidatorFactory");
        System.setProperty(AWS_PROP_REGION_NAME, "us-west-2");
        System.setProperty(ZTS_PROP_K8S_ATTESTATION_EXPECTED_AUDIENCE, "https://zts.athenz.io/zts/v1");
        InstanceK8SProvider provider = new InstanceK8SProvider();
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        when(authorizer.access(any(), any(), any(), any())).thenReturn(true);
        provider.setAuthorizer(authorizer);
        provider.initialize("k8sprovider", "com.yahoo.athenz.instance.provider.impl.InstanceK8SProvider", null, null);

        DefaultAWSElasticKubernetesServiceValidator.getInstance().jwtsHelper = Mockito.mock(JwtsHelper.class);
        when(DefaultAWSElasticKubernetesServiceValidator.getInstance().jwtsHelper.extractJwksUri(any(), any()))
                .thenReturn("file://" + jwksUri.getCanonicalPath());

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("my-domain");
        confirmation.setService("my-service");
        confirmation.setAttributes(new HashMap<>());
        confirmation.getAttributes().put(InstanceProvider.ZTS_INSTANCE_CLOUD, "aws");
        confirmation.getAttributes().put(InstanceProvider.ZTS_INSTANCE_AWS_ACCOUNT, "123456789012");
        confirmation.getAttributes().put(ZTS_INSTANCE_SAN_DNS,
                "my-service.my-domain.aws.athenz.cloud,abs2-ddce-221-32df.instanceid.athenz.aws.athenz.cloud");
        confirmation.setAttestationData("{\"identityToken\": \"" + createToken("system:serviceaccount:default:my-domain.my-service",
                "https://zts.athenz.io/zts/v1", "https://oidc.eks.us-east-1.amazonaws.com/id/123456789012") +  "\"}");

        StsClient sts = Mockito.mock(StsClient.class);
        StsClient stsOrig = DefaultAWSElasticKubernetesServiceValidator.getInstance().stsClient;
        DefaultAWSElasticKubernetesServiceValidator.getInstance().stsClient = sts;
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

            provider.confirmInstance(confirmation);
            assertEquals(confirmation.getAttributes().size(), 2);
            assertEquals(confirmation.getAttributes().get(InstanceProvider.ZTS_CERT_REFRESH), "false");
            assertEquals(confirmation.getAttributes().get(InstanceProvider.ZTS_CERT_EXPIRY_TIME), "10080");
        } catch (ResourceException re) {
            fail();
        }

        provider.close();
        System.clearProperty(ZTS_PROP_K8S_PROVIDER_DISTRIBUTION_VALIDATOR_FACTORY_CLASS);
        System.clearProperty(AWS_PROP_REGION_NAME);
        System.clearProperty(ZTS_PROP_K8S_ATTESTATION_EXPECTED_AUDIENCE);
        System.clearProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX);
        DefaultAWSElasticKubernetesServiceValidator.getInstance().jwtsHelper = new JwtsHelper();
        DefaultAWSElasticKubernetesServiceValidator.getInstance().stsClient = stsOrig;
        removeOpenIdConfigFile(configFile, jwksUri);
    }

    @Test
    public void testConfirmInstanceInvalidIssuer() {
        System.setProperty(InstanceGCPProvider.GCP_PROP_DNS_SUFFIX, "gcp.athenz.cloud");
        System.setProperty(ZTS_PROP_K8S_PROVIDER_DISTRIBUTION_VALIDATOR_FACTORY_CLASS,
                "com.yahoo.athenz.instance.provider.impl.DefaultKubernetesDistributionValidatorFactory");
        System.setProperty(AWS_PROP_REGION_NAME, "us-west-2");
        System.setProperty(ZTS_PROP_K8S_ATTESTATION_EXPECTED_AUDIENCE, "https://zts.athenz.io/zts/v1");
        InstanceK8SProvider provider = new InstanceK8SProvider();
        provider.initialize("k8sprovider", "com.yahoo.athenz.instance.provider.impl.InstanceK8SProvider", null, null);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("my-domain");
        confirmation.setService("my-service");
        confirmation.setAttributes(new HashMap<>());
        confirmation.getAttributes().put(InstanceProvider.ZTS_INSTANCE_CLOUD, "gcp");
        confirmation.getAttributes().put(InstanceProvider.ZTS_INSTANCE_GCP_PROJECT, "my-project");
        confirmation.getAttributes().put(ZTS_INSTANCE_SAN_DNS,
                "my-service.my-domain.gcp.athenz.cloud,abs2-ddce-221-32df.instanceid.athenz.gcp.athenz.cloud");
        confirmation.setAttestationData("{\"identityToken\": \"" + createToken("system:serviceaccount:default:my-domain.my-service",
                "https://zts.athenz.io/zts/v1", "invalid") +  "\"}");
        try {
            provider.confirmInstance(confirmation);
            fail();

        } catch (ResourceException re) {
            assertEquals(re.getCode(), ResourceException.FORBIDDEN);
        }
        provider.close();
        System.clearProperty(ZTS_PROP_K8S_PROVIDER_DISTRIBUTION_VALIDATOR_FACTORY_CLASS);
        System.clearProperty(AWS_PROP_REGION_NAME);
        System.clearProperty(ZTS_PROP_K8S_ATTESTATION_EXPECTED_AUDIENCE);
        System.clearProperty(InstanceGCPProvider.GCP_PROP_DNS_SUFFIX);
    }

    @Test
    public void testConfirmInstanceNoSupportedProvider() {
        System.setProperty(InstanceGCPProvider.GCP_PROP_DNS_SUFFIX, "gcp.athenz.cloud");
        System.setProperty(ZTS_PROP_K8S_PROVIDER_DISTRIBUTION_VALIDATOR_FACTORY_CLASS,
                "com.yahoo.athenz.instance.provider.impl.DefaultKubernetesDistributionValidatorFactory");
        System.setProperty(AWS_PROP_REGION_NAME, "us-west-2");
        System.setProperty(ZTS_PROP_K8S_ATTESTATION_EXPECTED_AUDIENCE, "https://zts.athenz.io/zts/v1");
        InstanceK8SProvider provider = new InstanceK8SProvider();
        provider.initialize("k8sprovider", "com.yahoo.athenz.instance.provider.impl.InstanceK8SProvider", null, null);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("my-domain");
        confirmation.setService("my-service");
        confirmation.setAttributes(new HashMap<>());
        confirmation.getAttributes().put(InstanceProvider.ZTS_INSTANCE_CLOUD, "azure");
        confirmation.getAttributes().put(InstanceProvider.ZTS_INSTANCE_GCP_PROJECT, "my-project");
        confirmation.getAttributes().put(ZTS_INSTANCE_SAN_DNS,
                "my-service.my-domain.gcp.athenz.cloud,abs2-ddce-221-32df.instanceid.athenz.gcp.athenz.cloud");
        confirmation.setAttestationData("{\"identityToken\": \"" + createToken("system:serviceaccount:default:my-domain.my-service",
                "https://zts.athenz.io/zts/v1", "https://container.googleapis.com/v1/projects/my-project/zones/us-east1-a/clusters/my-cluster") +  "\"}");
        try {
            provider.confirmInstance(confirmation);
            fail();

        } catch (ResourceException re) {
            assertEquals(re.getCode(), ResourceException.FORBIDDEN);
        }
        provider.close();
        System.clearProperty(ZTS_PROP_K8S_PROVIDER_DISTRIBUTION_VALIDATOR_FACTORY_CLASS);
        System.clearProperty(AWS_PROP_REGION_NAME);
        System.clearProperty(ZTS_PROP_K8S_ATTESTATION_EXPECTED_AUDIENCE);
        System.clearProperty(InstanceGCPProvider.GCP_PROP_DNS_SUFFIX);
    }

    @Test
    public void testConfirmInstanceInvalidAttestationData() {

        System.setProperty(InstanceGCPProvider.GCP_PROP_DNS_SUFFIX, "gcp.athenz.cloud");
        System.setProperty(ZTS_PROP_K8S_PROVIDER_DISTRIBUTION_VALIDATOR_FACTORY_CLASS,
                "com.yahoo.athenz.instance.provider.impl.DefaultKubernetesDistributionValidatorFactory");
        System.setProperty(AWS_PROP_REGION_NAME, "us-west-2");
        System.setProperty(ZTS_PROP_K8S_ATTESTATION_EXPECTED_AUDIENCE, "https://zts.athenz.io/zts/v1");

        InstanceK8SProvider provider = new InstanceK8SProvider();
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        when(authorizer.access(any(), any(), any(), any())).thenReturn(true);
        provider.setAuthorizer(authorizer);
        provider.initialize("k8sprovider", "com.yahoo.athenz.instance.provider.impl.InstanceK8SProvider", null, null);

        DefaultGCPGoogleKubernetesEngineValidator.getInstance().jwtsHelper = Mockito.mock(JwtsHelper.class);
        ClassLoader classLoader = this.getClass().getClassLoader();
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks_empty.json")).toString();
        when(DefaultGCPGoogleKubernetesEngineValidator.getInstance().jwtsHelper.extractJwksUri(any(), any()))
                .thenReturn(jwksUri);
        DefaultGCPGoogleKubernetesEngineValidator.getInstance().issuersMap.clear();

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("my-domain");
        confirmation.setService("my-service");
        confirmation.setAttributes(new HashMap<>());
        confirmation.getAttributes().put(InstanceProvider.ZTS_INSTANCE_CLOUD, "gcp");
        confirmation.getAttributes().put(InstanceProvider.ZTS_INSTANCE_GCP_PROJECT, "my-project");
        confirmation.getAttributes().put(ZTS_INSTANCE_SAN_DNS,
                "my-service.my-domain.gcp.athenz.cloud,abs2-ddce-221-32df.instanceid.athenz.gcp.athenz.cloud");
        confirmation.setAttestationData("{\"identityToken\": \"" + createToken("system:serviceaccount:default:my-domain.my-service",
                "https://zts.athenz.io/zts/v1", "https://container.googleapis.com/v1/projects/my-project/zones/us-east1-a/clusters/my-cluster") +  "\"}");

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException re) {
            assertEquals(re.getCode(), ResourceException.FORBIDDEN);
        }
        provider.close();

        System.clearProperty(ZTS_PROP_K8S_PROVIDER_DISTRIBUTION_VALIDATOR_FACTORY_CLASS);
        System.clearProperty(AWS_PROP_REGION_NAME);
        System.clearProperty(ZTS_PROP_K8S_ATTESTATION_EXPECTED_AUDIENCE);
        System.clearProperty(InstanceGCPProvider.GCP_PROP_DNS_SUFFIX);
        DefaultGCPGoogleKubernetesEngineValidator.getInstance().jwtsHelper = new JwtsHelper();
    }

    @Test
    public void testConfirmInstanceInvalidSanDNS() throws IOException {

        File configFile = new File("./src/test/resources/codesigning-openid.json");
        File jwksUri = new File("./src/test/resources/codesigning-jwks.json");
        PublicKey publicKey = Crypto.loadPublicKey(ecPublicKey);
        createOpenIdConfigFileWithKey(configFile, jwksUri, true, (ECPublicKey) publicKey);

        System.setProperty(InstanceGCPProvider.GCP_PROP_DNS_SUFFIX, "gcp.athenz.cloud");
        System.setProperty(ZTS_PROP_K8S_PROVIDER_DISTRIBUTION_VALIDATOR_FACTORY_CLASS,
                "com.yahoo.athenz.instance.provider.impl.DefaultKubernetesDistributionValidatorFactory");
        System.setProperty(AWS_PROP_REGION_NAME, "us-west-2");
        System.setProperty(ZTS_PROP_K8S_ATTESTATION_EXPECTED_AUDIENCE, "https://zts.athenz.io/zts/v1");

        InstanceK8SProvider provider = new InstanceK8SProvider();
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        when(authorizer.access(any(), any(), any(), any())).thenReturn(true);
        provider.setAuthorizer(authorizer);
        provider.initialize("k8sprovider", "com.yahoo.athenz.instance.provider.impl.InstanceK8SProvider", null, null);

        DefaultGCPGoogleKubernetesEngineValidator.getInstance().jwtsHelper = Mockito.mock(JwtsHelper.class);
        when(DefaultGCPGoogleKubernetesEngineValidator.getInstance().jwtsHelper.extractJwksUri(any(), any()))
                .thenReturn("file://" + jwksUri.getCanonicalPath());
        DefaultGCPGoogleKubernetesEngineValidator.getInstance().issuersMap.clear();

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("my-domain");
        confirmation.setService("my-service");
        confirmation.setAttributes(new HashMap<>());
        confirmation.getAttributes().put(InstanceProvider.ZTS_INSTANCE_CLOUD, "gcp");
        confirmation.getAttributes().put(InstanceProvider.ZTS_INSTANCE_GCP_PROJECT, "my-project");
        confirmation.getAttributes().put(ZTS_INSTANCE_SAN_DNS, "my-service.my-domain.gcp.athenz.cloud");
        confirmation.setAttestationData("{\"identityToken\": \"" + createToken("system:serviceaccount:default:my-domain.my-service",
                "https://zts.athenz.io/zts/v1", "https://container.googleapis.com/v1/projects/my-project/zones/us-east1-a/clusters/my-cluster") +  "\"}");
        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("Unable to validate certificate request hostnames"), ex.getMessage());
        }
        provider.close();
        System.clearProperty(ZTS_PROP_K8S_PROVIDER_DISTRIBUTION_VALIDATOR_FACTORY_CLASS);
        System.clearProperty(AWS_PROP_REGION_NAME);
        System.clearProperty(ZTS_PROP_K8S_ATTESTATION_EXPECTED_AUDIENCE);
        System.clearProperty(InstanceGCPProvider.GCP_PROP_DNS_SUFFIX);
        DefaultGCPGoogleKubernetesEngineValidator.getInstance().jwtsHelper = new JwtsHelper();
        removeOpenIdConfigFile(configFile, jwksUri);
    }
}
