/*
 * Copyright 2017 Yahoo Inc.
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
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import com.yahoo.athenz.zts.cert.CertRecordStoreConnection;
import com.yahoo.athenz.zts.cert.X509CertRecord;
import com.yahoo.rdl.JSON;

public class FileCertRecordStoreConnection implements CertRecordStoreConnection {
    
    File rootDir;
    public FileCertRecordStoreConnection(File rootDir) {
        this.rootDir = rootDir;
    }

    @Override
    public void close() {
    }
    
    @Override
    public void setOperationTimeout(int opTimeout) {
    }

    @Override
    public X509CertRecord getX509CertRecord(String provider, String instanceId) {
        return getCertRecord(provider, instanceId);
    }
    
    @Override
    public boolean updateX509CertRecord(X509CertRecord certRecord) {
        if (certRecord != null) {
            putCertRecord(certRecord);
        }
        return true;
    }
    
    @Override
    public boolean insertX509CertRecord(X509CertRecord certRecord) {
        if (certRecord != null) {
            putCertRecord(certRecord);
        }
        return true;
    }
    
    @Override
    public boolean deleteX509CertRecord(String provider, String instanceId) {
        deleteCertRecord(provider, instanceId);
        return true;
    }
    
    @Override
    public int deleteExpiredX509CertRecords(int expiryTimeMins) {
        String[] fnames = rootDir.list();
        if (fnames == null) {
            return 0;
        }
        long currentTime = System.currentTimeMillis();
        int count = 0;
        for (String fname : fnames) {
            
            // if the modification timestamp is older than
            // specified number of minutes then we'll delete it
            
            File f = new File(rootDir, fname);
            if (currentTime - f.lastModified() < expiryTimeMins * 60 * 1000) {
                continue;
            }
            //noinspection ResultOfMethodCallIgnored
            f.delete();
            count += 1;
        }
        return count;
    }
    
    private synchronized X509CertRecord getCertRecord(String provider, String instanceId) {
        File f = new File(rootDir, provider + "-" + instanceId);
        if (!f.exists()) {
            return null;
        }
        X509CertRecord record = null;
        try {
            Path path = Paths.get(f.toURI());
            record = JSON.fromBytes(Files.readAllBytes(path), X509CertRecord.class);
        } catch (IOException ignore) {
        }
        return record;
    }

    private synchronized void putCertRecord(X509CertRecord certRecord) {
        
        File f = new File(rootDir, certRecord.getProvider() + "-" + certRecord.getInstanceId());
        String data = JSON.string(certRecord);
        try {
            FileWriter fileWriter = new FileWriter(f);
            fileWriter.write(data);
            fileWriter.flush();
            fileWriter.close();
        } catch (IOException ignored) {
        }
    }

    private synchronized void deleteCertRecord(String provider, String instanceId) {
        File f = new File(rootDir, provider + "-" + instanceId);
        if (f.exists()) {
            if (!f.delete()) {
                throw new RuntimeException("Cannot delete file: " + f);
            }
        }
    }
}
