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

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.services.identitymanagement.AmazonIdentityManagement;
import com.amazonaws.services.identitymanagement.AmazonIdentityManagementClientBuilder;
import com.amazonaws.services.identitymanagement.model.ListOpenIDConnectProvidersRequest;
import com.amazonaws.services.identitymanagement.model.ListOpenIDConnectProvidersResult;
import com.amazonaws.services.identitymanagement.model.OpenIDConnectProviderListEntry;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import com.amazonaws.services.securitytoken.model.AssumeRoleRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleResult;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigCsv;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import org.eclipse.jetty.util.StringUtil;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.yahoo.athenz.common.server.util.config.ConfigManagerSingleton.CONFIG_MANAGER;
import static com.yahoo.athenz.instance.provider.InstanceProvider.ZTS_INSTANCE_AWS_ACCOUNT;
import static com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider.*;

public class DefaultAWSElasticKubernetesServiceValidator extends CommonKubernetesDistributionValidator {

    private static final DefaultAWSElasticKubernetesServiceValidator INSTANCE = new DefaultAWSElasticKubernetesServiceValidator();
    static final String AWS_EKS_OIDC_ISSUER_REGEX = "oidc\\.eks\\.[a-z0-9-]+\\.amazonaws\\.com";
    private static final Pattern AWS_EKS_OIDC_ISSUER_PATTERN = Pattern.compile(AWS_EKS_OIDC_ISSUER_REGEX);

    private static final String ZTS_PROP_K8S_PROVIDER_ATTESTATION_AWS_ASSUME_ROLE_NAME = "athenz.zts.k8s_provider_attestation_aws_assume_role_name";
    private static final String ASSUME_ROLE_NAME = System.getProperty(ZTS_PROP_K8S_PROVIDER_ATTESTATION_AWS_ASSUME_ROLE_NAME, "oidc-issuers-reader");

    AWSSecurityTokenService stsClient;
    String serverRegion;

    Set<String> awsDNSSuffixes = new HashSet<>();
    List<String> eksDnsSuffixes;
    DynamicConfigCsv eksClusterNames;        // list of eks cluster names

    public static DefaultAWSElasticKubernetesServiceValidator getInstance() {
        return INSTANCE;
    }
    private DefaultAWSElasticKubernetesServiceValidator() {
    }
    @Override
    public void initialize() {
        super.initialize();
        serverRegion = System.getProperty(AWS_PROP_REGION_NAME);
        // Create an STS client using default credentials
        stsClient = AWSSecurityTokenServiceClientBuilder.standard()
                .withRegion(serverRegion)
                .withCredentials(DefaultAWSCredentialsProviderChain.getInstance())
                .build();

        final String dnsSuffix = System.getProperty(AWS_PROP_DNS_SUFFIX);
        if (!StringUtil.isEmpty(dnsSuffix)) {
            awsDNSSuffixes.addAll(Arrays.asList(dnsSuffix.split(",")));
        }
        // get our allowed eks dns suffixes
        eksDnsSuffixes = InstanceUtils.processK8SDnsSuffixList(AWS_PROP_EKS_DNS_SUFFIX);
        // get our dynamic list of eks cluster names
        eksClusterNames = new DynamicConfigCsv(CONFIG_MANAGER, AWS_PROP_EKS_CLUSTER_NAMES, null);
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

        if (!verifyIssuerPresenceInDomainAWSAccount(issuer,
                confirmation.getAttributes().get(ZTS_INSTANCE_AWS_ACCOUNT))) {
            return null;
        }
        return issuer;
    }

    boolean verifyIssuerPresenceInDomainAWSAccount(final String issuer,
                                                   final String awsAccount) {
        boolean result = false;

        String roleArn = String.format("arn:aws:iam::%s:role/%s", awsAccount, ASSUME_ROLE_NAME);
        String roleSessionName = ASSUME_ROLE_NAME + "-Session";

        // Assume the role in the target AWS account
        AssumeRoleRequest assumeRoleRequest = new AssumeRoleRequest()
                .withRoleArn(roleArn)
                .withRoleSessionName(roleSessionName);
        AssumeRoleResult assumeRoleResult = stsClient.assumeRole(assumeRoleRequest);
        BasicSessionCredentials sessionCredentials = new BasicSessionCredentials(
                assumeRoleResult.getCredentials().getAccessKeyId(),
                assumeRoleResult.getCredentials().getSecretAccessKey(),
                assumeRoleResult.getCredentials().getSessionToken()
        );

        AmazonIdentityManagement iamClient = AmazonIdentityManagementClientBuilder.standard()
                .withRegion(serverRegion)
                .withCredentials(new AWSStaticCredentialsProvider(sessionCredentials))
                .build();

        // Call the IAM API to get the list of OIDC issuers
        ListOpenIDConnectProvidersRequest listRequest = new ListOpenIDConnectProvidersRequest();
        ListOpenIDConnectProvidersResult listResult = iamClient.listOpenIDConnectProviders(listRequest);
        List<OpenIDConnectProviderListEntry> oidcIssuers = listResult.getOpenIDConnectProviderList();
        if (oidcIssuers != null) {
            String issuerWithoutProtocol = issuer.replaceFirst("^https://", "");
            for (OpenIDConnectProviderListEntry oidcIssuer : oidcIssuers) {
                if (oidcIssuer != null && oidcIssuer.getArn() != null && oidcIssuer.getArn().endsWith(issuerWithoutProtocol)) {
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
}
