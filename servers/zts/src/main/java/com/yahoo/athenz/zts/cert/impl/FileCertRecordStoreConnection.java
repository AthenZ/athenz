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
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import com.yahoo.athenz.common.server.cert.CertRecordStoreConnection;
import com.yahoo.athenz.common.server.cert.X509CertRecord;
import com.yahoo.athenz.common.server.util.FilesHelper;
import com.yahoo.rdl.JSON;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FileCertRecordStoreConnection implements CertRecordStoreConnection {

    private static final Logger LOGGER = LoggerFactory.getLogger(FileCertRecordStoreConnection.class);

    File rootDir;
    FilesHelper filesHelper;

    public FileCertRecordStoreConnection(File rootDir) {
        this.rootDir = rootDir;
        this.filesHelper = new FilesHelper();
    }

    @Override
    public void close() {
    }
    
    @Override
    public void setOperationTimeout(int opTimeout) {
    }

    @Override
    public X509CertRecord getX509CertRecord(String provider, String instanceId, String service) {
        return getCertRecord(provider, instanceId, service);
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
    public boolean deleteX509CertRecord(String provider, String instanceId, String service) {
        deleteCertRecord(provider, instanceId, service);
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
            
            File file = new File(rootDir, fname);
            if (notExpired(currentTime, file.lastModified(), expiryTimeMins)) {
                continue;
            }
            //noinspection ResultOfMethodCallIgnored
            file.delete();
            count += 1;
        }
        return count;
    }

    @Override
    public List<X509CertRecord> updateUnrefreshedCertificatesNotificationTimestamp(String lastNotifiedServer,
                                                                                   long lastNotifiedTime,
                                                                                   String provider) {
        // Currently unimplemented for File
        return new ArrayList<>();
    }

    boolean notExpired(long currentTime, long lastModified, long expiryTimeMins) {
        return (currentTime - lastModified < expiryTimeMins * 60 * 1000);
    }

    private String getRecordFileName(final String provider, final String instanceId, final String service) {
        return provider + "-" + instanceId + "-" + service;
    }

    private synchronized X509CertRecord getCertRecord(String provider, String instanceId, String service) {
        File file = new File(rootDir, getRecordFileName(provider, instanceId, service));
        if (!file.exists()) {
            return null;
        }
        X509CertRecord record = null;
        try {
            Path path = Paths.get(file.toURI());
            record = JSON.fromBytes(Files.readAllBytes(path), X509CertRecord.class);
        } catch (IOException ex) {
            LOGGER.error("Unable to get certificate record", ex);
        }
        return record;
    }

    private synchronized void putCertRecord(X509CertRecord certRecord) {
        
        File file = new File(rootDir, getRecordFileName(certRecord.getProvider(), certRecord.getInstanceId(), certRecord.getService()));
        String data = JSON.string(certRecord);
        try (FileWriter fileWriter = new FileWriter(file)) {
            fileWriter.write(data);
            fileWriter.flush();
        } catch (IOException ex) {
            LOGGER.error("Unable to save certificate record", ex);
        }
    }

    private synchronized void deleteCertRecord(String provider, String instanceId, String service) {
        File file = new File(rootDir, getRecordFileName(provider, instanceId, service));
        try {
            filesHelper.delete(file);
        } catch (IOException ex) {
            LOGGER.error("Unable to delete certificate record", ex);
        }
    }
}
