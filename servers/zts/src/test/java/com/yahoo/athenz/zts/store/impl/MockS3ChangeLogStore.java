/*
 * Copyright 2019 Oath Holdings, Inc.
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
import org.mockito.Mockito;

import java.util.concurrent.ExecutorService;

class MockS3ChangeLogStore extends S3ChangeLogStore {

    int execService = 0;
    ExecutorService executorService = Mockito.mock(ExecutorService.class);
    AmazonS3 awsS3Client;
    public MockS3ChangeLogStore(CloudStore cloudStore) {
        super(cloudStore);
        awsS3Client = mock(AmazonS3.class);
    }

    public MockS3ChangeLogStore(CloudStore cloudStore, int executorService) {
        super(cloudStore);
        awsS3Client = mock(AmazonS3.class);
        this.execService = executorService;
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

    @Override
    public ExecutorService getExecutorService() {
        if (execService == 1) {
            return executorService;
        } else {
            return executorService = super.getExecutorService();
        }
    }
}
