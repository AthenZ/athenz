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
package com.yahoo.athenz.zts.cert.impl;

import java.io.File;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.cert.CertRecordStore;
import com.yahoo.athenz.common.server.cert.CertRecordStoreFactory;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.ZTSImpl;

public class FileCertRecordStoreFactory implements CertRecordStoreFactory {

    @Override
    public CertRecordStore create(PrivateKeyStore pkeyStore) {

        String homeDir = System.getProperty(ZTSConsts.ZTS_PROP_CERT_FILE_STORE_PATH,
                ZTSImpl.getRootDir() + "/var/zts_server");
        String fileDirName = System.getProperty(ZTSConsts.ZTS_PROP_CERT_FILE_STORE_NAME,
                "zts_cert_records");
        String path = homeDir + File.separator + fileDirName;
        return new FileCertRecordStore(new File(path));
    }
}
