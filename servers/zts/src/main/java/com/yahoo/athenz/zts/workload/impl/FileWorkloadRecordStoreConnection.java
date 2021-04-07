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

import com.yahoo.athenz.auth.util.AthenzUtils;
import com.yahoo.athenz.common.server.util.FilesHelper;
import com.yahoo.athenz.common.server.workload.WorkloadRecord;
import com.yahoo.athenz.common.server.workload.WorkloadRecordStoreConnection;
import com.yahoo.rdl.JSON;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class FileWorkloadRecordStoreConnection implements WorkloadRecordStoreConnection {

    private static final Logger LOGGER = LoggerFactory.getLogger(FileWorkloadRecordStoreConnection.class);

    File rootDir;
    FilesHelper filesHelper;

    public FileWorkloadRecordStoreConnection(File rootDir) {
        this.rootDir = rootDir;
        this.filesHelper = new FilesHelper();
    }

    @Override
    public void close() {
        LOGGER.info("closing file connection");
    }

    @Override
    public void setOperationTimeout(int opTimeout) {
        LOGGER.info("setting file op timeout");
    }

    @Override
    public List<WorkloadRecord> getWorkloadRecordsByService(String domain, String service) {

        File[] foundFiles = rootDir.listFiles((dir, name) -> name.startsWith(AthenzUtils.getPrincipalName(domain, service)));
        List<WorkloadRecord> workloadRecords = new ArrayList<>();
        for (File file : foundFiles) {
            workloadRecords.add(getWorkloadRecord(file));
        }
        return workloadRecords;
    }

    @Override
    public List<WorkloadRecord> getWorkloadRecordsByIp(String ip) {
        File[] foundFiles = rootDir.listFiles((dir, name) -> name.startsWith(ip));
        List<WorkloadRecord> workloadRecords = new ArrayList<>();
        for (File file : foundFiles) {
            workloadRecords.add(getWorkloadRecord(file));
        }
        return workloadRecords;
    }

    WorkloadRecord getWorkloadRecord(File file) {
        WorkloadRecord record = null;
        try {
            Path path = Paths.get(file.toURI());
            record = JSON.fromBytes(Files.readAllBytes(path), WorkloadRecord.class);
        } catch (IOException ex) {
            LOGGER.error("Unable to get workload record:{}", ex.getMessage());
        }
        return record;
    }

    @Override
    public synchronized boolean updateWorkloadRecord(WorkloadRecord workloadRecord) {
        return insertWorkloadRecord(workloadRecord);
    }

    @Override
    public synchronized boolean insertWorkloadRecord(WorkloadRecord workloadRecord) {
        File file = new File(rootDir, getRecordFileNameByService(workloadRecord.getService(), workloadRecord.getInstanceId(), workloadRecord.getIp()));
        String data = JSON.string(workloadRecord);
        writeWorkloadRecord(file, data);
        file = new File(rootDir, getRecordFileNameByIp(workloadRecord.getService(), workloadRecord.getInstanceId(), workloadRecord.getIp()));
        writeWorkloadRecord(file, data);
        return true;
    }

    void writeWorkloadRecord(File file, String data) {
        try (FileWriter fileWriter = new FileWriter(file)) {
            fileWriter.write(data);
            fileWriter.flush();
        } catch (IOException ex) {
            LOGGER.error("Unable to save workload record:{}", ex.getMessage());
        }
    }

    private String getRecordFileNameByService(final String service, final String instanceId, final String ip) {
        return service + "-" + instanceId + "-" + ip;
    }

    private String getRecordFileNameByIp(final String service, final String instanceId, final String ip) {
        return ip + "-" + instanceId + "-" + service;
    }

}
