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
package com.yahoo.athenz.zts.workload.impl;

import com.yahoo.athenz.common.server.workload.WorkloadRecordStore;
import com.yahoo.athenz.common.server.workload.WorkloadRecordStoreConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;

public class FileWorkloadRecordStore implements WorkloadRecordStore {

    private static final Logger LOGGER = LoggerFactory.getLogger(FileWorkloadRecordStore.class);
    File rootDir;

    public FileWorkloadRecordStore(File rootDirectory) {
        if (!rootDirectory.exists()) {
            if (!rootDirectory.mkdirs()) {
                error("cannot create specified root: " + rootDirectory);
            }
        } else {
            if (!rootDirectory.isDirectory()) {
                error("specified root is not a directory: " + rootDirectory);
            }
        }
        this.rootDir = rootDirectory;
    }

    @Override
    public WorkloadRecordStoreConnection getConnection() {
        return new FileWorkloadRecordStoreConnection(rootDir);
    }

    @Override
    public void setOperationTimeout(int opTimeout) {
        LOGGER.info("setting imaginary file op time out");
    }

    @Override
    public void clearConnections() {
        LOGGER.info("cleating imaginary file connections");
    }

    static void error(String msg) {
        throw new RuntimeException("FileObjectStore: " + msg);
    }
}
