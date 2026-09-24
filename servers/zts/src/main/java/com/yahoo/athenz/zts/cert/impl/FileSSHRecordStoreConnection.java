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

import com.yahoo.athenz.common.server.ssh.SSHCertRecord;
import com.yahoo.athenz.common.server.ssh.SSHRecordStoreConnection;
import com.yahoo.athenz.common.server.util.FilesHelper;
import com.yahoo.rdl.JSON;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class FileSSHRecordStoreConnection implements SSHRecordStoreConnection {

    private static final Logger LOGGER = LoggerFactory.getLogger(FileSSHRecordStoreConnection.class);

    File rootDir;
    FilesHelper filesHelper;

    public FileSSHRecordStoreConnection(File rootDir) {
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
    public SSHCertRecord getSSHCertRecord(String instanceId, String service) {
        return getCertRecord(instanceId, service);
    }
    
    @Override
    public boolean updateSSHCertRecord(SSHCertRecord certRecord) {
        return certRecord == null || putCertRecord(certRecord);
    }

    @Override
    public boolean insertSSHCertRecord(SSHCertRecord certRecord) {
        return certRecord == null || putCertRecord(certRecord);
    }

    @Override
    public boolean deleteSSHCertRecord(String instanceId, String service) {
        return deleteCertRecord(instanceId, service);
    }
    
    @Override
    public int deleteExpiredSSHCertRecords(int expiryTimeMins, int limit) {
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
            if (count == limit) {
                break;
            }
        }
        return count;
    }

    boolean notExpired(long currentTime, long lastModified, int expiryTimeMins) {
        return (currentTime - lastModified < expiryTimeMins * 60 * 1000);
    }

    private String getRecordFileName(final String instanceId, final String service) {
        return instanceId + "-" + service;
    }

    File getRecordFile(final String instanceId, final String service) {

        // make sure the record file is directly within our root
        // directory. the name must not include any path separators
        // (or nul characters) so it's always a single path component
        // and the resolved path must still be within the root directory

        final String fileName = getRecordFileName(instanceId, service);
        final Path rootPath = rootDir.toPath().toAbsolutePath().normalize();
        if (fileName.indexOf('/') != -1 || fileName.indexOf('\\') != -1 || fileName.indexOf('\0') != -1
                || !rootPath.resolve(fileName).normalize().startsWith(rootPath)) {
            LOGGER.error("Invalid ssh certificate record file: {}", fileName);
            return null;
        }
        return rootPath.resolve(fileName).toFile();
    }

    private synchronized SSHCertRecord getCertRecord(String instanceId, String service) {
        File file = getRecordFile(instanceId, service);
        if (file == null || !file.exists()) {
            return null;
        }
        SSHCertRecord record = null;
        try {
            Path path = Paths.get(file.toURI());
            record = JSON.fromBytes(Files.readAllBytes(path), SSHCertRecord.class);
        } catch (IOException ex) {
            LOGGER.error("Unable to get ssh certificate record", ex);
        }
        return record;
    }

    private synchronized boolean putCertRecord(SSHCertRecord certRecord) {

        File file = getRecordFile(certRecord.getInstanceId(), certRecord.getService());
        if (file == null) {
            return false;
        }
        String data = JSON.string(certRecord);
        try (FileWriter fileWriter = new FileWriter(file)) {
            fileWriter.write(data);
            fileWriter.flush();
        } catch (IOException ex) {
            LOGGER.error("Unable to get save ssh certificate record", ex);
            return false;
        }
        return true;
    }

    private synchronized boolean deleteCertRecord(String instanceId, String service) {
        File file = getRecordFile(instanceId, service);
        if (file == null) {
            return false;
        }
        try {
            filesHelper.delete(file);
        } catch (IOException ex) {
            LOGGER.error("Unable to delete ssh certificate record", ex);
            return false;
        }
        return true;
    }
}
