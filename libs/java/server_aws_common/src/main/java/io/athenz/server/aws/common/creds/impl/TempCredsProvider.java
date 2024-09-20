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
import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Struct;
import com.yahoo.rdl.Timestamp;
import org.eclipse.jetty.client.ContentResponse;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.Request;
import org.eclipse.jetty.http.HttpMethod;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.services.sts.model.AssumeRoleResponse;
import software.amazon.awssdk.services.sts.model.Credentials;

import java.net.URI;

import static com.yahoo.athenz.common.ServerCommonConsts.ZTS_PROP_AWS_REGION_NAME;

public class TempCredsProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(TempCredsProvider.class);

    private static final String AWS_METADATA_BASE_URI = "http://169.254.169.254/latest";
    private static final String AWS_METADATA_TOKEN_URI = "http://169.254.169.254/latest/api/token";
    private static final String AWS_METADATA_TOKEN_HEADER = "X-aws-ec2-metadata-token";
    private static final String AWS_METADATA_TOKEN_TTL_HEADER = "X-aws-ec2-metadata-token-ttl-seconds";

    public static final String ZTS_PROP_AWS_ROLE_SESSION_NAME = "athenz.zts.aws_role_session_name";

    String awsRole = null;
    String awsRegion;
    String awsRoleSessionName;
    AwsBasicCredentials credentials;
    private HttpClient httpClient;

    public TempCredsProvider() throws ServerResourceException {

        // Instantiate and start our HttpClient

        httpClient = new HttpClient();
        setupHttpClient(httpClient);

        // check to see if we are given region name

        awsRegion = System.getProperty(ZTS_PROP_AWS_REGION_NAME);

        // fetch the default session name if one is configured

        awsRoleSessionName = System.getProperty(ZTS_PROP_AWS_ROLE_SESSION_NAME);
    }

    public void initialize() throws ServerResourceException {
        // initialize and load our bootstrap data

        if (!loadBootMetaData()) {
            throw new ServerResourceException(ServerResourceException.INTERNAL_SERVER_ERROR, "Unable to load boot data");
        }

        // finally fetch the role credentials

        if (!fetchRoleCredentials())  {
            throw new ServerResourceException(ServerResourceException.INTERNAL_SERVER_ERROR, "Unable to fetch aws role credentials");
        }
    }

    void setupHttpClient(HttpClient client) throws ServerResourceException {

        client.setFollowRedirects(false);
        try {
            client.start();
        } catch (Exception ex) {
            LOGGER.error("CloudStore: unable to start http client", ex);
            throw new ServerResourceException(ServerResourceException.INTERNAL_SERVER_ERROR, "Http client not available");
        }
    }

    public void close() {
        stopHttpClient();
    }


    public void setHttpClient(HttpClient client) {
        stopHttpClient();
        httpClient = client;
    }

    private void stopHttpClient() {
        if (httpClient == null) {
            return;
        }
        try {
            httpClient.stop();
        } catch (Exception ignored) {
        }
    }

    boolean loadBootMetaData() {

        // first load the dynamic document

        final String document = getMetaData("/dynamic/instance-identity/document");
        if (document == null) {
            return false;
        }

        if (!parseInstanceInfo(document)) {
            return false;
        }

        // then the document signature

        final String docSignature = getMetaData("/dynamic/instance-identity/pkcs7");
        if (docSignature == null) {
            return false;
        }

        // next the iam profile data

        final String iamRole = getMetaData("/meta-data/iam/info");
        if (iamRole == null) {
            return false;
        }

        // now parse and extract the profile details. we'll catch
        // all possible index out of bounds exceptions here and just
        // report the error and return false

        if (!parseIamRoleInfo(iamRole)) {
            return false;
        }

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("CloudStore: service meta information:");
            LOGGER.debug("CloudStore: role:   {}", awsRole);
            LOGGER.debug("CloudStore: region: {}", awsRegion);
        }
        return true;
    }

    public boolean fetchRoleCredentials() {

        // verify that we have a valid awsRole already retrieved

        if (StringUtil.isEmpty(awsRole)) {
            LOGGER.error("CloudStore: awsRole is not available to fetch role credentials");
            return false;
        }

        final String creds = getMetaData("/meta-data/iam/security-credentials/" + awsRole);
        if (creds == null) {
            return false;
        }

        Struct credsStruct = JSON.fromString(creds, Struct.class);
        if (credsStruct == null) {
            LOGGER.error("CloudStore: unable to parse role credentials data: {}", creds);
            return false;
        }

        String accessKeyId = credsStruct.getString("AccessKeyId");
        String secretAccessKey = credsStruct.getString("SecretAccessKey");

        credentials = AwsBasicCredentials.builder()
                .accessKeyId(accessKeyId)
                .secretAccessKey(secretAccessKey)
                .build();

        return true;
    }

    boolean parseInstanceInfo(String document) {

        Struct instStruct = JSON.fromString(document, Struct.class);
        if (instStruct == null) {
            LOGGER.error("CloudStore: unable to parse instance identity document: {}", document);
            return false;
        }

        // if we're overriding the region name, then we'll
        // extract that value here

        if (StringUtil.isEmpty(awsRegion)) {
            awsRegion = instStruct.getString("region");
            if (StringUtil.isEmpty(awsRegion)) {
                LOGGER.error("CloudStore: unable to extract region from instance identity document: {}", document);
                return false;
            }
        }

        return true;
    }

    boolean parseIamRoleInfo(final String iamRole) {

        Struct iamRoleStruct = JSON.fromString(iamRole, Struct.class);
        if (iamRoleStruct == null) {
            LOGGER.error("CloudStore: unable to parse iam role data: {}", iamRole);
            return false;
        }

        // extract and parse our profile arn
        // "InstanceProfileArn" : "arn:aws:iam::1111111111111:instance-profile/iaas.athenz.zts,athenz",

        final String profileArn = iamRoleStruct.getString("InstanceProfileArn");
        if (StringUtil.isEmpty(profileArn)) {
            LOGGER.error("CloudStore: unable to extract InstanceProfileArn from iam role data: {}", iamRole);
            return false;
        }

        return parseInstanceProfileArn(profileArn);
    }

    boolean parseInstanceProfileArn(final String profileArn) {

        // "InstanceProfileArn" : "arn:aws:iam::1111111111111:instance-profile/iaas.athenz.zts,athenz",

        if (!profileArn.startsWith("arn:aws:iam::")) {
            LOGGER.error("CloudStore: InstanceProfileArn does not start with 'arn:aws:iam::' : {}",
                    profileArn);
            return false;
        }

        int idx = profileArn.indexOf(":instance-profile/");
        if (idx == -1) {
            LOGGER.error("CloudStore: unable to parse InstanceProfileArn: {}", profileArn);
            return false;
        }

        final String awsProfile = profileArn.substring(idx + ":instance-profile/".length());

        // make sure we have valid profile and account data

        if (awsProfile.isEmpty()) {
            LOGGER.error("CloudStore: unable to extract profile/account data from InstanceProfileArn: {}",
                    profileArn);
            return false;
        }

        // we need to extract the role from the profile

        idx = awsProfile.indexOf(',');
        if (idx == -1) {
            awsRole = awsProfile;
        } else {
            awsRole = awsProfile.substring(0, idx);
        }

        return true;
    }

    String getMetaData(String path) {

        // first we need to get a token for IMDSv2 support
        // if the token is not available we'll just try without
        // it to see if we can get the data with v1 support

        final String token = processHttpRequest(HttpMethod.PUT, AWS_METADATA_TOKEN_URI, AWS_METADATA_TOKEN_TTL_HEADER, "60");
        if (StringUtil.isEmpty(token)) {
            LOGGER.info("unable to get token for IMDSv2 support");
        }
        return processHttpRequest(HttpMethod.GET, AWS_METADATA_BASE_URI + path, AWS_METADATA_TOKEN_HEADER, token);
    }

    String processHttpRequest(HttpMethod httpMethod, String uri, String headerName, String headerValue) {

        ContentResponse response;
        try {
            Request request = httpClient.newRequest(URI.create(uri)).method(httpMethod);
            if (!StringUtil.isEmpty(headerName) && !StringUtil.isEmpty(headerValue)) {
                request.headers((fields) -> fields.put(headerName, headerValue));
            }
            response = request.send();
        } catch (Exception ex) {
            LOGGER.error("unable to fetch requested uri '{}':{}", uri, ex.getMessage());
            return null;
        }
        if (response.getStatus() != 200) {
            LOGGER.error("unable to fetch requested uri '{}' status:{}", uri, response.getStatus());
            return null;
        }

        String data = response.getContentAsString();
        if (StringUtil.isEmpty(data)) {
            LOGGER.error("received empty response from uri '{}' status:{}", uri, response.getStatus());
            return null;
        }

        return data;
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
                .credentialsProvider(StaticCredentialsProvider.create(credentials))
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

}
