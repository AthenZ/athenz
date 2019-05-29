/*
 * Copyright 2016 Yahoo Inc.
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
package com.yahoo.athenz.zts.store.impl;

import static org.mockito.Mockito.mock;

import com.amazonaws.services.s3.AmazonS3;
import com.yahoo.athenz.zts.store.CloudStore;
import com.yahoo.athenz.zts.store.impl.S3ChangeLogStore;

class MockS3ChangeLogStore extends S3ChangeLogStore {
    
    public MockS3ChangeLogStore(CloudStore cloudStore) {
        super(cloudStore);
        awsS3Client = mock(AmazonS3.class);
    }

    void resetAWSS3Client() {
        awsS3Client = null;
    }

    @Override
    AmazonS3 getS3Client() {
        if (awsS3Client == null) {
            awsS3Client = mock(AmazonS3.class);
        }
        return awsS3Client;
    }
}
