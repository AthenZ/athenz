/*
 * Copyright 2016 Yahoo Inc.
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
package com.yahoo.athenz.zpe;

import java.io.File;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Used in monitoring the policy directory for file changes.
 */
public class ZpeUpdMonitor implements Runnable {
    private static final Logger LOG = LoggerFactory.getLogger(ZpeUpdMonitor.class);

    private String dirName;
    private boolean firstRun = true;
    private final ZpeUpdPolLoader updLoader;
    private volatile boolean shutdownThread = false;

    private java.io.FilenameFilter polFileNameFilter = (dir, name) -> name.endsWith(".pol");

    ZpeUpdMonitor(final ZpeUpdPolLoader zpeUpdLoader) {
        updLoader = zpeUpdLoader;
        dirName = updLoader.getDirName();
    }

    public void cancel() {
        shutdownThread = true;
    }
    
    public File[] loadFileStatus() {

        if (dirName == null) {
            return null;
        }
        // read all the file names in the policy directory and add to the list

        File pdir = new File(dirName);
        File [] files = pdir.listFiles(polFileNameFilter);
        if (files == null || files.length == 0) {
            if (pdir.exists()) {
                LOG.error("loadFileStatus: the directory={} exists, but there are no policy files in it", dirName);
            } else {
                LOG.error("loadFileStatus: the directory={} does NOT exist", dirName);
            }
        }
        return files;
    }

    private void logRunMsg(Exception exc) {

        dirName = dirName == null ? "MISSING-POL-DIR-NAME" : dirName;
        String msg = "Reload directory=" + dirName;

        if (exc == null) {
            LOG.debug(msg);
        } else {
            LOG.error("{}, exc: {}", msg, exc.getMessage());
        }
    }

    @Override
    public void run() {
        if (updLoader == null) {
            LOG.error("run: No ZpeUpdPolLoader to monitor");
            return;
        }

        if (shutdownThread) {
            LOG.warn("run: monitor told to shutdown");
            return;
        }

        // perform cleanup of RoleTokens and AccessTokens
        // expired ones will be removed

        ZpeUpdPolLoader.cleanupRoleTokenCache();
        ZpeUpdPolLoader.cleanupAccessTokenCache();

        try {
            updLoader.loadDb(loadFileStatus());
            if (firstRun) {
                firstRun = false;
                synchronized (updLoader) {
                    updLoader.notify();
                }
            }
        } catch (Exception exc) {
            logRunMsg(exc);
            return;
        }

        if (LOG.isDebugEnabled()) {
            logRunMsg(null);
        }
    }
}

