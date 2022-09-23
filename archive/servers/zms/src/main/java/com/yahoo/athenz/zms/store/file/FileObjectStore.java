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
package com.yahoo.athenz.zms.store.file;

import java.io.File;

import com.yahoo.athenz.zms.store.ObjectStore;
import com.yahoo.athenz.zms.store.ObjectStoreConnection;

public class FileObjectStore implements ObjectStore {

    final File rootDir;
    File quotaDir;
    
    public FileObjectStore(File rootDirectory, File quotaDirectory) {
        verifyDirectory(rootDirectory);
        verifyDirectory(quotaDirectory);
        this.rootDir = rootDirectory;
        this.quotaDir = quotaDirectory;
    }

    void verifyDirectory(File directory) {
        if (!directory.exists()) {
            if (!directory.mkdirs()) {
                error("cannot create specified root: " + directory);
            }
        } else {
            if (!directory.isDirectory()) {
                error("specified root is not a directory: " + directory);
            }
        }
    }
    
    @Override
    public ObjectStoreConnection getConnection(boolean autoCommit, boolean readWrite) {
        return new FileConnection(rootDir, quotaDir);
    }
    
    @Override
    public void setOperationTimeout(int opTimeout) {
    }
    
    @Override
    public void clearConnections() {
    }

    static void error(String msg) {
        throw new RuntimeException("FileObjectStore: " + msg);
    }
}
