/*
 *  Copyright 2020 Verizon Media
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.common.server.store;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.BasicSessionCredentials;
import com.yahoo.athenz.zms.ResourceException;
import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Struct;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.api.ContentResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

public class AWSInstanceMetadataFetcher implements Closeable {
    private static final Logger LOGGER = LoggerFactory.getLogger(AWSInstanceMetadataFetcher.class);

    String awsRole = null;

    String awsRegion;
    private HttpClient httpClient;

    public AWSInstanceMetadataFetcher() {
        httpClient = new HttpClient();
        setupHttpClient(httpClient);
    }

    boolean loadBootMetaData(boolean getAwsRegion) {

        // first load the dynamic document

        String document = getMetaData("/dynamic/instance-identity/document");
        if (document == null) {
            return false;
        }

        if (!parseInstanceInfo(document, getAwsRegion)) {
            LOGGER.error("CloudStore: unable to parse instance identity document: {}", document);
            return false;
        }

        // then the document signature

        String docSignature = getMetaData("/dynamic/instance-identity/pkcs7");
        if (docSignature == null) {
            return false;
        }

        // next the iam profile data

        String iamRole = getMetaData("/meta-data/iam/info");
        if (iamRole == null) {
            return false;
        }

        // now parse and extract the profile details. we'll catch
        // all possible index out of bounds exceptions here and just
        // report the error and return false

        if (!parseIamRoleInfo(iamRole)) {
            LOGGER.error("CloudStore: unable to parse iam role data: {}", iamRole);
            return false;
        }

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("CloudStore: service meta information:");
            LOGGER.debug("CloudStore: role:   {}", awsRole);
            LOGGER.debug("CloudStore: region: {}", awsRegion);
        }
        return true;
    }

    boolean parseInstanceInfo(String document, boolean getAwsRegion) {

        Struct instStruct = JSON.fromString(document, Struct.class);
        if (instStruct == null) {
            LOGGER.error("CloudStore: unable to parse instance identity document: {}", document);
            return false;
        }

        // if we're overriding the region name, then we'll
        // extract that value here

        if (getAwsRegion) {
            // Extract the awsRegion. We'll only use it if it isn't overridden by property
            awsRegion = instStruct.getString("region");
            if (awsRegion == null || awsRegion.isEmpty()) {
                LOGGER.error("CloudStore: unable to extract region from instance identity document: {}",
                        document);
                return false;
            }
        }

        return true;
    }

    boolean parseIamRoleInfo(String iamRole) {

        Struct iamRoleStruct = JSON.fromString(iamRole, Struct.class);
        if (iamRoleStruct == null) {
            LOGGER.error("CloudStore: unable to parse iam role data: {}", iamRole);
            return false;
        }

        // extract and parse our profile arn
        // "InstanceProfileArn" : "arn:aws:iam::1111111111111:instance-profile/iaas.athenz.zts,athenz",

        String profileArn = iamRoleStruct.getString("InstanceProfileArn");
        if (profileArn == null || profileArn.isEmpty()) {
            LOGGER.error("CloudStore: unable to extract InstanceProfileArn from iam role data: {}", iamRole);
            return false;
        }

        return parseInstanceProfileArn(profileArn);
    }

    boolean parseInstanceProfileArn(String profileArn) {

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

        final String baseUri = "http://169.254.169.254/latest";
        ContentResponse response;
        try {
            response = httpClient.GET(baseUri + path);
        } catch (InterruptedException | ExecutionException | TimeoutException ex) {
            LOGGER.error("CloudStore: unable to fetch requested uri '{}':{}",
                    path, ex.getMessage());
            return null;
        }
        if (response.getStatus() != 200) {
            LOGGER.error("CloudStore: unable to fetch requested uri '{}' status:{}",
                    path, response.getStatus());
            return null;
        }

        String data = response.getContentAsString();
        if (data == null || data.isEmpty()) {
            LOGGER.error("CloudStore: received empty response from uri '{}' status:{}",
                    path, response.getStatus());
            return null;
        }

        return data;
    }

    public void setHttpClient(HttpClient client) {
        stopHttpClient();
        httpClient = client;
    }

    void setupHttpClient(HttpClient client) {

        client.setFollowRedirects(false);
        client.setStopTimeout(1000);
        try {
            client.start();
        } catch (Exception ex) {
            LOGGER.error("CloudStore: unable to start http client", ex);
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR,
                    "Http client not available");
        }
    }

    AWSCredentials fetchRoleCredentials() {

        // verify that we have a valid awsRole already retrieved

        if (awsRole == null || awsRole.isEmpty()) {
            LOGGER.error("CloudStore: awsRole is not available to fetch role credentials");
            return null;
        }

        final String creds = getMetaData("/meta-data/iam/security-credentials/" + awsRole);
        if (creds == null) {
            return null;
        }

        Struct credsStruct = JSON.fromString(creds, Struct.class);
        if (credsStruct == null) {
            LOGGER.error("CloudStore: unable to parse role credentials data: {}", creds);
            return null;
        }

        String accessKeyId = credsStruct.getString("AccessKeyId");
        String secretAccessKey = credsStruct.getString("SecretAccessKey");
        String token = credsStruct.getString("Token");

        return new BasicSessionCredentials(accessKeyId, secretAccessKey, token);
    }
    
    @Override
    public void close() {
        stopHttpClient();
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
}
