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
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.yahoo.athenz.zms.ResourceException;

public class S3ClientFactory {
    private final AWSCredentialsRefresher awsCredentialsRefresher;

    public S3ClientFactory() {
        // Instantiate credentials fetcher
        awsCredentialsRefresher = new AWSCredentialsRefresher();
    }

    public S3ClientFactory(AWSCredentialsRefresher awsCredentialsRefresher) {
        this.awsCredentialsRefresher = awsCredentialsRefresher;
    }

    public AmazonS3 create() {
        AWSCredentials credentials = awsCredentialsRefresher.getCredentials();
        if (credentials == null) {
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR,
                    "AWS Role credentials are not available");
        }

        String awsRegion = awsCredentialsRefresher.getAwsRegion();
        if (awsRegion == null) {
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR,
                    "AWS region is not available");
        }

        return AmazonS3ClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(credentials))
                .withRegion(Regions.fromName(awsRegion))
                .build();
    }
}
