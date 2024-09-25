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
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigBoolean;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigCsv;
import com.yahoo.athenz.instance.provider.AttrValidator;
import com.yahoo.athenz.instance.provider.AttrValidatorFactory;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.lang.invoke.MethodHandles;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.iam.model.ListOpenIdConnectProvidersRequest;
import software.amazon.awssdk.services.iam.model.ListOpenIdConnectProvidersResponse;
import software.amazon.awssdk.services.iam.model.OpenIDConnectProviderListEntry;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.services.sts.model.AssumeRoleResponse;

import static com.yahoo.athenz.common.server.util.config.ConfigManagerSingleton.CONFIG_MANAGER;
import static com.yahoo.athenz.instance.provider.InstanceProvider.ZTS_INSTANCE_AWS_ACCOUNT;
import static com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider.*;

public class DefaultAWSElasticKubernetesServiceValidator extends CommonKubernetesDistributionValidator {

    private static final Logger LOGGER = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    private static final DefaultAWSElasticKubernetesServiceValidator INSTANCE = new DefaultAWSElasticKubernetesServiceValidator();
    static final String AWS_EKS_OIDC_ISSUER_REGEX = "oidc\\.eks\\.[a-z0-9-]+\\.amazonaws\\.com";
    private static final Pattern AWS_EKS_OIDC_ISSUER_PATTERN = Pattern.compile(AWS_EKS_OIDC_ISSUER_REGEX);

    private static final String ZTS_PROP_K8S_PROVIDER_ATTESTATION_AWS_ASSUME_ROLE_NAME = "athenz.zts.k8s_provider_attestation_aws_assume_role_name";
    private static final String ASSUME_ROLE_NAME = System.getProperty(ZTS_PROP_K8S_PROVIDER_ATTESTATION_AWS_ASSUME_ROLE_NAME, "oidc-issuers-reader");
    static final String ZTS_PROP_K8S_PROVIDER_AWS_ATTR_VALIDATOR_FACTORY_CLASS = "athenz.zts.k8s_provider_aws_attr_validator_factory_class";

    StsClient stsClient;
    String serverRegion;

    Set<String> awsDNSSuffixes = new HashSet<>();
    List<String> eksDnsSuffixes;
    DynamicConfigCsv eksClusterNames;        // list of eks cluster names
    
    private static final String ZTS_PROP_K8S_PROVIDER_AWS_ATTESTATION_USING_IAM_ROLE = "athenz.zts.k8s_provider_aws_attestation_using_iam_role";
    DynamicConfigBoolean useIamRoleForIssuerAttestation;
    AttrValidator attrValidator;

    public static DefaultAWSElasticKubernetesServiceValidator getInstance() {
        return INSTANCE;
    }

    private DefaultAWSElasticKubernetesServiceValidator() {
    }

    static AttrValidator newAttrValidator(final SSLContext sslContext) {
        final String factoryClass = System.getProperty(ZTS_PROP_K8S_PROVIDER_AWS_ATTR_VALIDATOR_FACTORY_CLASS);
        LOGGER.info("AWS K8S AttributeValidatorFactory class: {}", factoryClass);
        if (factoryClass == null) {
            return null;
        }

        AttrValidatorFactory attrValidatorFactory;
        try {
            attrValidatorFactory = (AttrValidatorFactory) Class.forName(factoryClass).getConstructor().newInstance();
        } catch (Exception e) {
            LOGGER.error("Invalid AttributeValidatorFactory class: {}", factoryClass, e);
            throw new IllegalArgumentException("Invalid AttributeValidatorFactory class");
        }

        return attrValidatorFactory.create(sslContext);
    }

    @Override
    public void initialize(final SSLContext sslContext, Authorizer authorizer) {
        super.initialize(sslContext, authorizer);
        serverRegion = System.getProperty(AWS_PROP_REGION_NAME);

        useIamRoleForIssuerAttestation = new DynamicConfigBoolean(CONFIG_MANAGER, ZTS_PROP_K8S_PROVIDER_AWS_ATTESTATION_USING_IAM_ROLE, true);

        if (useIamRoleForIssuerValidation()) {
            // Create an STS client using default credentials
            stsClient = StsClient.builder().credentialsProvider(DefaultCredentialsProvider.builder().build())
                    .region(Region.of(serverRegion)).build();
        }
        final String dnsSuffix = System.getProperty(AWS_PROP_DNS_SUFFIX);
        if (!StringUtil.isEmpty(dnsSuffix)) {
            awsDNSSuffixes.addAll(Arrays.asList(dnsSuffix.split(",")));
        }
        // get our allowed eks dns suffixes
        eksDnsSuffixes = InstanceUtils.processK8SDnsSuffixList(AWS_PROP_EKS_DNS_SUFFIX);
        // get our dynamic list of eks cluster names
        eksClusterNames = new DynamicConfigCsv(CONFIG_MANAGER, AWS_PROP_EKS_CLUSTER_NAMES, null);

        this.attrValidator = newAttrValidator(sslContext);
    }

    @Override
    public String validateIssuer(InstanceConfirmation confirmation, IdTokenAttestationData attestationData, StringBuilder errMsg) {

        String issuer = getIssuerFromToken(attestationData, errMsg);
        if (StringUtil.isEmpty(issuer)) {
            return null;
        }

        String issuerDomain = InstanceUtils.extractURLDomainName(issuer);
        if (issuerDomain == null) {
            return null;
        }
        Matcher matcher = AWS_EKS_OIDC_ISSUER_PATTERN.matcher(issuerDomain);
        if (!matcher.matches()) {
            return null;
        }

        if (useIamRoleForIssuerValidation()) {
            String awsAccount = confirmation.getAttributes().get(ZTS_INSTANCE_AWS_ACCOUNT);
            if (!verifyIssuerPresenceInDomainAWSAccount(issuer, awsAccount)) {
                return null;
            }
            // If the issuer is present in the same AWS account as the requested identity
            // then we should use the same for the launch authorization
            confirmation.getAttributes().put(ZTS_INSTANCE_ISSUER_AWS_ACCOUNT, awsAccount);
        } else {
            if (attrValidator != null) {
                confirmation.getAttributes().put(ZTS_INSTANCE_UNATTESTED_ISSUER, issuer);
                // Confirm the issuer as per the attribute validator
                if (!attrValidator.confirm(confirmation)) {
                    return null;
                }
            }
        }

        final String domainName = confirmation.getDomain();
        final String serviceName = confirmation.getService();
        // attribute set after iam role validation or attribute validation
        final String issuerAwsAccount = confirmation.getAttributes().get(ZTS_INSTANCE_ISSUER_AWS_ACCOUNT);
        final String resource = String.format("%s:%s:%s", domainName, serviceName, issuerAwsAccount);

        Principal principal = SimplePrincipal.create(domainName, serviceName, (String) null);
        boolean accessCheck = authorizer.access(ACTION_LAUNCH, resource, principal, null);
        if (!accessCheck) {
            errMsg.append("eks launch authorization check failed for action: ").append(ACTION_LAUNCH)
                    .append(" resource: ").append(resource);
            return null;
        }

        return issuer;
    }

    IamClient getIamClient(final String awsAccount) {

        final String roleArn = String.format("arn:aws:iam::%s:role/%s", awsAccount, ASSUME_ROLE_NAME);
        final String roleSessionName = ASSUME_ROLE_NAME + "-Session";

        // Assume the role in the target AWS account

        AssumeRoleRequest assumeRoleRequest = AssumeRoleRequest.builder()
                .roleArn(roleArn).roleSessionName(roleSessionName).build();
        AssumeRoleResponse assumeRoleResponse = stsClient.assumeRole(assumeRoleRequest);

        // Create Static Credentials Provider

        StaticCredentialsProvider credentialsProvider = StaticCredentialsProvider.create(
                AwsSessionCredentials.create(assumeRoleResponse.credentials().accessKeyId(),
                        assumeRoleResponse.credentials().secretAccessKey(),
                        assumeRoleResponse.credentials().sessionToken()));

        // Create IAM Client

        return IamClient.builder().credentialsProvider(credentialsProvider).region(Region.of(serverRegion)).build();
    }

    boolean verifyIssuerPresenceInDomainAWSAccount(final String issuer, final String awsAccount) {

        boolean result = false;

        // get our IAM Client

        IamClient iamClient = getIamClient(awsAccount);

        // Call the IAM API to get the list of OIDC issuers

        ListOpenIdConnectProvidersRequest request = ListOpenIdConnectProvidersRequest.builder().build();
        ListOpenIdConnectProvidersResponse response = iamClient.listOpenIDConnectProviders(request);
        List<OpenIDConnectProviderListEntry> oidcIssuers = response.openIDConnectProviderList();
        if (oidcIssuers != null) {
            String issuerWithoutProtocol = issuer.replaceFirst("^https://", "");
            for (OpenIDConnectProviderListEntry oidcIssuer : oidcIssuers) {
                if (oidcIssuer != null && oidcIssuer.arn() != null && oidcIssuer.arn().endsWith(issuerWithoutProtocol)) {
                    result = true;
                    break;
                }
            }
        }
        return result;
    }

    @Override
    public boolean validateSanDNSEntries(InstanceConfirmation confirmation, StringBuilder errMsg) {

        StringBuilder instanceId = new StringBuilder(256);
        final Map<String, String> instanceAttributes = confirmation.getAttributes();
        final String awsAccount = InstanceUtils.getInstanceProperty(instanceAttributes, ZTS_INSTANCE_AWS_ACCOUNT);
        if (StringUtil.isEmpty(awsAccount)) {
            errMsg.append("Unable to find AWS account number");
            return false;
        }
        if (!InstanceUtils.validateCertRequestSanDnsNames(instanceAttributes, confirmation.getDomain(),
                confirmation.getService(), awsDNSSuffixes, eksDnsSuffixes, eksClusterNames.getStringsList(),
                true, instanceId, null)) {
            errMsg.append("Unable to validate certificate request hostnames");
            return false;
        }
        return true;
    }

    boolean useIamRoleForIssuerValidation() {
        return Boolean.TRUE.equals(useIamRoleForIssuerAttestation.get());
    }
}
