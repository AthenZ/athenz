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

package com.yahoo.athenz.zts.cert.impl;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.yahoo.athenz.zts.AWSCredentialsProviderImpl;

public class DynamoDBClientAndCredentials {
    private AmazonDynamoDB amazonDynamoDB;
    private AWSCredentialsProviderImpl awsCredentialsProvider;

    public DynamoDBClientAndCredentials(AmazonDynamoDB amazonDynamoDB, AWSCredentialsProviderImpl awsCredentialsProvider) {
        this.amazonDynamoDB = amazonDynamoDB;
        this.awsCredentialsProvider = awsCredentialsProvider;
    }

    public AmazonDynamoDB getAmazonDynamoDB() {
        return amazonDynamoDB;
    }

    public AWSCredentialsProviderImpl getAwsCredentialsProvider() {
        return awsCredentialsProvider;
    }
}
