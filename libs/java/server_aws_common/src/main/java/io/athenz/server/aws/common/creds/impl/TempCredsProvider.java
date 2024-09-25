/*
 * Copyright The Athenz Authors.
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

package io.athenz.server.aws.common.creds.impl;

import com.yahoo.athenz.zts.AWSTemporaryCredentials;
import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.rdl.Timestamp;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.auth.credentials.InstanceProfileCredentialsProvider;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.services.sts.model.AssumeRoleResponse;
import software.amazon.awssdk.services.sts.model.Credentials;

import static com.yahoo.athenz.common.ServerCommonConsts.ZTS_PROP_AWS_REGION_NAME;

public class TempCredsProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(TempCredsProvider.class);

    public static final String ZTS_PROP_AWS_ROLE_SESSION_NAME = "athenz.zts.aws_role_session_name";

    String awsRegion;
    String awsRoleSessionName;
    InstanceProfileCredentialsProvider credentialsProvider;

    public TempCredsProvider() throws ServerResourceException {

        // check to see if we are given region name

        awsRegion = System.getProperty(ZTS_PROP_AWS_REGION_NAME);

        // fetch the default session name if one is configured

        awsRoleSessionName = System.getProperty(ZTS_PROP_AWS_ROLE_SESSION_NAME);
    }

    public void initialize() throws ServerResourceException {

         credentialsProvider = InstanceProfileCredentialsProvider.builder()
                .asyncCredentialUpdateEnabled(true).build();
    }

    String getAssumeRoleSessionName(final String principal) {

        // if we're configured to use a specific session name
        // then that's what we'll use and ignore the principal name

        if (!StringUtil.isEmpty(awsRoleSessionName)) {
            return awsRoleSessionName;
        }

        // make sure the role session name is valid and not too long
        // and does not contain any invalid characters. From aws docs:
        //   Length Constraints: Minimum length of 2. Maximum length of 64.
        //   Pattern: [\w+=,.@-]*
        // if the Athenz principal identity is longer than 64 characters,
        // we'll truncate the principal name to 60 and add insert ... in
        // the middle to indicate truncation

        return (principal.length() > 64) ?
                principal.substring(0, 30) + "..." + principal.substring(principal.length() - 30) : principal;
    }

    AssumeRoleRequest getAssumeRoleRequest(final String account, final String roleName, Integer durationSeconds,
            final String externalId, final String principal) {

        // assume the target role to get the credentials for the client
        // aws format is arn:aws:iam::<account-id>:role/<role-name>

        final String arn = "arn:aws:iam::" + account + ":role/" + roleName;

        AssumeRoleRequest.Builder builder = AssumeRoleRequest.builder()
                .roleArn(arn)
                .roleSessionName(getAssumeRoleSessionName(principal));
        if (durationSeconds != null && durationSeconds > 0) {
            builder = builder.durationSeconds(durationSeconds);
        }
        if (!StringUtil.isEmpty(externalId)) {
            builder = builder.externalId(externalId);
        }
        return builder.build();
    }

    StsClient getTokenServiceClient() {

        return StsClient.builder()
                .credentialsProvider(credentialsProvider)
                .region(Region.of(awsRegion))
                .build();
    }

    public AWSTemporaryCredentials getTemporaryCredentials(final String account, final String roleName,
            final String principal, Integer durationSeconds, final String externalId, StringBuilder errorMessage)
            throws ServerResourceException {

        AssumeRoleRequest req = getAssumeRoleRequest(account, roleName, durationSeconds, externalId, principal);

        try {
            StsClient client = getTokenServiceClient();
            AssumeRoleResponse res = client.assumeRole(req);

            Credentials awsCreds = res.credentials();
            return new AWSTemporaryCredentials()
                    .setAccessKeyId(awsCreds.accessKeyId())
                    .setSecretAccessKey(awsCreds.secretAccessKey())
                    .setSessionToken(awsCreds.sessionToken())
                    .setExpiration(Timestamp.fromMillis(awsCreds.expiration().toEpochMilli()));

        } catch (AwsServiceException ex) {

            int statusCode;
            String errMessage;
            if (ex.awsErrorDetails() == null || ex.awsErrorDetails().sdkHttpResponse() == null) {
                statusCode = ServerResourceException.BAD_REQUEST;
                errMessage = ex.getMessage();
            } else {
                statusCode = ex.awsErrorDetails().sdkHttpResponse().statusCode();
                errMessage = ex.awsErrorDetails().errorMessage();
            }
            LOGGER.error("assumeAWSRole - unable to assume role: {}, error: {}, status code: {}",
                    req.roleArn(), ex.getMessage(), statusCode);

            errorMessage.append(errMessage);
            throw new ServerResourceException(statusCode, "Unable to assume role: " + req.roleArn());

        } catch (Exception ex) {

            LOGGER.error("assumeAWSRole - unable to assume role: {}, error: {}",
                    req.roleArn(), ex.getMessage());

            errorMessage.append(ex.getMessage());
            throw new ServerResourceException(ServerResourceException.BAD_REQUEST, "Unable to assume role: " + req.roleArn());
        }
    }

    public void close() {
        if (credentialsProvider != null) {
            credentialsProvider.close();
        }
    }
}
