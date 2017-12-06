/**
 * Copyright 2017 Yahoo Holdings, Inc.
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
package com.oath.auth;

import static java.nio.file.StandardWatchEventKinds.ENTRY_MODIFY;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * @author charlesk
 *
 */
public class CertWatcher implements Runnable {
    private static Logger LOGGER = LoggerFactory.getLogger(CertWatcher.class);

    private Path watchPath;
    private WatchService watcher;
    private volatile boolean stopped = false;
    private final CertWatcherHandler certWatcherHandler;
    
    /**
     * 
     * @param watchPath Path to the file to be watched for modified event.
     * @param certWatcherHandler Call back handler be to triggered during modified event.
     * @throws IOException
     */
    public CertWatcher(String watchPath, CertWatcherHandler certWatcherHandler) throws IOException {
        if (watchPath != null && !watchPath.isEmpty()) {
            URI uri = URI.create(watchPath);
            this.watchPath = Paths.get(uri.getPath());
            Path watchPathDir = this.watchPath.getParent();
            this.watcher = watchPathDir.getFileSystem().newWatchService();
            watchPathDir.register(watcher, ENTRY_MODIFY);
        }
        this.certWatcherHandler = certWatcherHandler;
        Thread t = new Thread(this);
        t.setDaemon(true);
        LOGGER.info("Starting CertWatcher on path: {}", watchPath);
        t.start();
    }
    
    @Override
    public void run() {
        while (!stopped) {
            handleWatchEvent(this.watcher, this.watchPath);
        }
    }
    
    public void stop() {
        LOGGER.info("Stopping CertWatcher");
        this.stopped = true;
    }

    private void handleWatchEvent(WatchService watcher, Path storeFile) {
        if (null == watcher) {
            return;
        }
        WatchKey watchKey;
        try {
            watchKey = watcher.take();
        } catch (InterruptedException e) {
            LOGGER.warn(e.getMessage());
            return;
        }
        for (WatchEvent event : watchKey.pollEvents()) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("event kind: {}, event context: {}", event.kind(), event.context());
            }
            if (ENTRY_MODIFY.equals(event.kind()) && event.context().equals(storeFile.getFileName())) {
                try {
                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug("About to reload SSL credentials");
                    }
                    certWatcherHandler.certChanged();
                } catch (Exception ex) {
                    LOGGER.warn("Error reloading SSL credentials", ex);
                }
            }
        }
        watchKey.reset();
    }

}
