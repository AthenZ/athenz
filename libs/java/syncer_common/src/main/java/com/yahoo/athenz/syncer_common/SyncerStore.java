/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.syncer_common;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import java.util.Set;

/**
 * Save / load syncer state from disc.
 * Used for starting fync from last successful run.
 */
public class SyncerStore {
    private static final String STOP_FNAME          = "stopSync";
    private static final String LAST_SUCCESSFUL_RUN_FNAME = "lastSuccessfulRunTime";

    private static final Logger LOGGER = LoggerFactory.getLogger(SyncerStore.class);

    File rootDir;
    ObjectMapper jsonMapper;

    public SyncerStore() {
        // initialize our jackson object mapper

        jsonMapper = new ObjectMapper();
        jsonMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

        // setup our directory for storing domain files
        String rootDirectory = System.getProperty("syncer.workdir", "/tmp/syncer/");
        rootDir = new File(rootDirectory);

        if (!rootDir.exists()) {
            if (!rootDir.mkdirs()) {
                error("cannot create specified root: " + rootDirectory);
            }
        } else {
            if (!rootDir.isDirectory()) {
                error("specified root is not a directory: " + rootDirectory);
            }
        }
    }

    public Long getLastRunTime() {
        String lastSuccessfulRunTime = retrieveLastSuccessfulRunTime();
        LOGGER.info("Last successful sync: {}", lastSuccessfulRunTime);
        if (lastSuccessfulRunTime.isEmpty()) {
            return 0L;
        }
        return Long.valueOf(lastSuccessfulRunTime);
    }

    public boolean stopFileExists() {
        File file = new File(rootDir, STOP_FNAME);
        return file.exists();
    }

    public void setLastSuccessfulRunTimestamp(String lastSuccessfulRunTime) {

        if (lastSuccessfulRunTime == null) {
            delete(LAST_SUCCESSFUL_RUN_FNAME);
        } else {
            // update the last successful runtime
            put(LAST_SUCCESSFUL_RUN_FNAME, lastSuccessfulRunTime.getBytes(StandardCharsets.UTF_8));
        }
    }

    private String retrieveLastSuccessfulRunTime() {
        String lastSuccessfulRunTime = get(LAST_SUCCESSFUL_RUN_FNAME, String.class);
        return (lastSuccessfulRunTime == null) ? "" : lastSuccessfulRunTime;
    }

    private synchronized <T> T get(String name, Class<T> classType) {

        File file = new File(rootDir, name);
        if (!file.exists()) {
            return null;
        }

        try {
            return jsonMapper.readValue(file, classType);
        } catch (Exception ex) {
            LOGGER.error("Unable to retrieve file: {} error: {}", file.getAbsolutePath(), ex.getMessage());
        }
        return null;
    }

    private synchronized void delete(String name) {
        File file = new File(rootDir, name);
        if (!file.exists()) {
            return;
        }

        try {
            Files.delete(file.toPath());
        } catch (Exception exc) {
            error("delete: Cannot delete file or directory: " + name + " : exc: " + exc);
        }
    }

    private synchronized void put(String name, byte[] data) {

        File file = new File(rootDir, name);
        if (!file.exists()) {
            setupSyncTimeFile(file);
        }
        Path path = Paths.get(file.toURI());
        try {
            Files.write(path, data);
        } catch (IOException ex) {
            error("unable to save domain file: " + file.getPath() + " error: " + ex.getMessage());
        }
    }

    private void setupSyncTimeFile(File file) {

        try {
            new FileOutputStream(file).close();
            file.setLastModified(System.currentTimeMillis());
            Path path = file.toPath();
            Set<PosixFilePermission> perms = EnumSet.of(PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE);
            Files.setPosixFilePermissions(path, perms);
        } catch (IOException ex) {
            ex.printStackTrace();
            error("setupSyncTimeFile: unable to setup file with permissions: " + ex.getMessage());
        }
    }

    private static void error(String msg) {
        LOGGER.error(msg);
        throw new RuntimeException("Syncer: " + msg);
    }
}
