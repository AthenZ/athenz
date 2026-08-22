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
import com.yahoo.athenz.common.server.util.Utils;
import com.yahoo.athenz.instance.provider.AWSAttestationValidator;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityRequest;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityResponse;

import javax.net.ssl.SSLContext;

import static com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider.AWS_PROP_REGION_NAME;

/**
 * AWSStsCredentialsAttestationValidator verifies an instance identity by using
 * the AWS STS temporary credentials provided in the attestation data to call
 * GetCallerIdentity and confirming the returned ARN matches the requested role
 * in the given AWS account. This is the traditional Athenz AWS attestation
 * mechanism.
 */
public class AWSStsCredentialsAttestationValidator implements AWSAttestationValidator {

    private static final Logger LOGGER = LoggerFactory.getLogger(AWSStsCredentialsAttestationValidator.class);

    String awsRegion;

    @Override
    public void initialize(SSLContext sslContext, Authorizer authorizer) {
        awsRegion = System.getProperty(AWS_PROP_REGION_NAME);
    }

    StsClient getInstanceClient(AWSAttestationData info) {

        final String accessKey = info.getAccess();
        if (StringUtil.isEmpty(accessKey)) {
            LOGGER.error("getInstanceClient: No access key available in instance document");
            return null;
        }

        final String secretKey = info.getSecret();
        if (StringUtil.isEmpty(secretKey)) {
            LOGGER.error("getInstanceClient: No secret key available in instance document");
            return null;
        }

        final String sessionToken = info.getToken();
        if (StringUtil.isEmpty(sessionToken)) {
            LOGGER.error("getInstanceClient: No session token available in instance document");
            return null;
        }

        // Create Static Credentials Provider

        StaticCredentialsProvider credentialsProvider = StaticCredentialsProvider.create(
                AwsSessionCredentials.create(accessKey, secretKey, sessionToken));

        // Create STS Client

        return StsClient.builder().credentialsProvider(credentialsProvider).region(Region.of(awsRegion)).build();
    }

    @Override
    public boolean validateIdentity(InstanceConfirmation confirmation, AWSAttestationData info,
            final String awsAccount, StringBuilder errMsg) {

        if (StringUtil.isEmpty(awsRegion)) {
            errMsg.append("aws region is not configured");
            return false;
        }
        try (StsClient stsClient = getInstanceClient(info)) {
            if (stsClient == null) {
                errMsg.append("unable to get AWS STS client object");
                return false;
            }

            GetCallerIdentityRequest request = GetCallerIdentityRequest.builder().build();
            GetCallerIdentityResponse response = stsClient.getCallerIdentity(request);
            if (response == null) {
                errMsg.append("unable to get caller identity");
                return false;
            }

            for (String account : Utils.parseAwsAccounts(awsAccount)) {
                final String arn = "arn:aws:sts::" + account + ":assumed-role/" + info.getRole() + "/";
                if (response.arn().startsWith(arn)) {
                    return true;
                }
            }

            errMsg.append("ARN mismatch - account(s): ").append(awsAccount)
                    .append(" caller-identity: ").append(response.arn());
            LOGGER.error("validateIdentity - ARN mismatch - account(s): {} caller-identity: {}",
                    awsAccount, response.arn());
            return false;

        } catch (Exception ex) {
            errMsg.append("unable to get caller identity: ").append(ex.getMessage());
            LOGGER.error("validateIdentity - unable to get caller identity: {}", ex.getMessage());
            return false;
        }
    }
}
