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
package com.yahoo.athenz.zms.store.impl;

import java.io.File;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.zms.ZMSConsts;
import com.yahoo.athenz.zms.ZMSImpl;
import com.yahoo.athenz.zms.store.ObjectStore;
import com.yahoo.athenz.zms.store.ObjectStoreFactory;
import com.yahoo.athenz.zms.store.file.FileObjectStore;

public class FileObjectStoreFactory implements ObjectStoreFactory {

    @Override
    public ObjectStore create(PrivateKeyStore pkeyStore) {

        String homeDir = System.getProperty(ZMSConsts.ZMS_PROP_FILE_STORE_PATH,
                ZMSImpl.getRootDir() + "/var/zms_server");
        String fileDirName = System.getProperty(ZMSConsts.ZMS_PROP_FILE_STORE_NAME, "zms_root");
        String quotaDirName = System.getProperty(ZMSConsts.ZMS_PROP_FILE_STORE_QUOTA, "zms_quota");
        String filePath = homeDir + File.separator + fileDirName;
        String quotaPath = homeDir + File.separator + quotaDirName;
        return new FileObjectStore(new File(filePath), new File(quotaPath));
    }
}
