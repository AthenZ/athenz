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
package com.oath.auth;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KeyRefresher {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeyRefresher.class);

    private Thread scanForFileChangesThread;
    private boolean shutdown = false; //only for testing
    //60 seconds * 60 (min in an hour)
    public static final int DEFAULT_RETRY_CHECK_FREQUENCY = 60_000 * 60;

    private final MessageDigest md = MessageDigest.getInstance("MD5");
    private final byte[] lastPublicCertManagerChecksum = new byte[md.getDigestLength()];
    private final byte[] lastPrivateKeyManagerChecksum = new byte[md.getDigestLength()];
    private final byte[] lastTrustManagerChecksum = new byte[md.getDigestLength()];

    private final String athenzPublicCert;
    private final String athenzPrivateKey;
    private final TrustStore trustStore;
    private final KeyManagerProxy keyManagerProxy;
    private final TrustManagerProxy trustManagerProxy;

    private int retryFrequency = DEFAULT_RETRY_CHECK_FREQUENCY;
    
    private final KeyRefresherListener keyRefresherListener;

    /**
     * this method should be used in the following way
     * 1) invoked primarily by the Utils.generateKeyRefresher method
     * 2) an outside callers can then call getKeyManagerProxy() and getTrustManagerProxy()
     * 3) pass those proxies into the Utils.BuildSSLContext method
     * 4) use that SSLContext when starting a server
     * 5) once server is started, call startup() (in this class)
     * <p>
     *  at this point, when the private/public keys / trustStore files change, it will automatically
     *  update the SSL context so any new connections will use the new values, and no old connections
     *  will fail.  So presumably when those connections die (from expiring TTL values) they will create
     *  new connections and leverage the new values.  No interruption to the service will be experienced.
     * <p>
     * Once created, it needs to be turned on using the startup() method.  It will then
     * wake up once an hour and check the various public/private keys and trust store files
     * to see if they have been updated.  If so, it will automatically update the SSL context
     * correlating to the client/server that the *ManagerProxy objects are tied to.
     * <p>
     * If you want to stop this thread, you need to call the shutdown() method
     *
     * @param athenzPublicCert the file path to public certificate file
     * @param athenzPrivateKey the file path to the private key
     * @param trustStore trust store
     * @param keyManagerProxy the keyManagerProxy used in the existing server/client
     * @param trustManagerProxy the keyManagerProxy used in the existing server/client
     * @throws NoSuchAlgorithmException this is only thrown if we cannot use MD5 hashing
     */
    public KeyRefresher(final String athenzPublicCert, final String athenzPrivateKey, final TrustStore trustStore,
            final KeyManagerProxy keyManagerProxy, final TrustManagerProxy trustManagerProxy) throws NoSuchAlgorithmException {
        this(athenzPublicCert, athenzPrivateKey, trustStore, keyManagerProxy, trustManagerProxy, null);
    }
    
    /**
     * 
     * @param athenzPublicCert x.509 certificate file path
     * @param athenzPrivateKey private key path
     * @param trustStore truststore path
     * @param keyManagerProxy key manager proxy object
     * @param trustManagerProxy trust manager proxy object
     * @param keyRefresherListener key refresher listener - called when key/cert have been reloaded
     * @throws NoSuchAlgorithmException is thrown when a particular cryptographic algorithm is requested but is not available in the environment
     */
    public KeyRefresher(final String athenzPublicCert, final String athenzPrivateKey, final TrustStore trustStore,
                        final KeyManagerProxy keyManagerProxy, final TrustManagerProxy trustManagerProxy,
                        final KeyRefresherListener keyRefresherListener)
            throws NoSuchAlgorithmException {
        this.athenzPublicCert = athenzPublicCert;
        this.athenzPrivateKey = athenzPrivateKey;
        this.trustStore = trustStore;
        this.keyManagerProxy = keyManagerProxy;
        this.trustManagerProxy = trustManagerProxy;
        this.keyRefresherListener = keyRefresherListener;
    }

    /**
     * Return key manager proxy object
     * @return key manager proxy object
     */
    public KeyManagerProxy getKeyManagerProxy() {
        return keyManagerProxy;
    }

    /**
     * Return trust manager proxy object
     * @return trust manager proxy object
     */
    public TrustManagerProxy getTrustManagerProxy() {
        return trustManagerProxy;
    }

    private void scanForFileChanges() {
        scanForFileChangesThread = new Thread(() -> {
            // run loop contents here
            while (!shutdown) {
                try {
                    if (haveFilesBeenChanged(trustStore.getFilePath(), lastTrustManagerChecksum)) {
                        trustManagerProxy.setTrustManager(trustStore.getTrustManagers());
                        if (LOGGER.isDebugEnabled()) {
                            LOGGER.debug("KeyRefresher detected changes. Reloaded Trust Managers");
                        }
                    }
                    //we want to check both files (public + private) and update both checksums
                    boolean keyFilesChanged = haveFilesBeenChanged(athenzPrivateKey, lastPrivateKeyManagerChecksum);
                    keyFilesChanged = haveFilesBeenChanged(athenzPublicCert, lastPublicCertManagerChecksum) || keyFilesChanged;
                    if (keyFilesChanged) {
                        
                        keyManagerProxy.setKeyManager(Utils.getKeyManagers(athenzPublicCert, athenzPrivateKey));
                        if (LOGGER.isDebugEnabled()) {
                            LOGGER.debug("KeyRefresher detected changes. Reloaded Key managers");
                        }
                        //Signal key change event
                        if (keyRefresherListener != null) {
                            keyRefresherListener.onKeyChangeEvent();
                        }
                    }
                } catch (Exception ex) {
                    // if we could not reload the SSL context (but we tried) we will
                    // ignore it and hope it works on the next loop
                    LOGGER.error("Error loading ssl context", ex);
                }
                try {
                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug("KeyRefresher sleeping for {} ms", retryFrequency);
                    }
                    if (!shutdown) {
                        Thread.sleep(retryFrequency);
                    }
                } catch (InterruptedException ignored) {
                }
            }
        });
        scanForFileChangesThread.setDaemon(true);
        scanForFileChangesThread.setName("scanForFileChanges" + " started at:" + System.currentTimeMillis());
        scanForFileChangesThread.start();
        LOGGER.info("Started KeyRefresher thread.");
    }

    /**
     * shutdown the key refresher
     */
    public void shutdown() {
        shutdown = true;
        if (scanForFileChangesThread != null) {
            scanForFileChangesThread.interrupt();
        }
    }

    /**
     * Start the refresher file scan task
     */
    public void startup() {
        startup(DEFAULT_RETRY_CHECK_FREQUENCY);
    }

    /**
     * Start the refresher file scan task with given interval
     * @param retryFrequency how often check for file changes
     */
    public void startup(int retryFrequency) {
        this.retryFrequency = retryFrequency;
        shutdown = false;
        scanForFileChanges();
    }

    /**
     * If the checksum for the file has changed, then update the checksum
     * and return true.  else return false
     * @param filePath file to check for changes
     * @param checksum current checksum. will be updated with a new value if the file was changed
     * @return true if file was changed, false otherwise
     */
    protected boolean haveFilesBeenChanged(final String filePath, byte[] checksum) {

        // if we don't have an absolute path for our file path then it
        // was retrieved from our resource and as such there is no need
        // to check to see if it was changed or not.

        final Path path = Paths.get(filePath);
        if (!path.isAbsolute()) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Relative path: {} specified - ignoring change check", filePath);
            }
            return false;
        }

        try (InputStream is = Files.newInputStream(path)) {
            byte[] buffer = new byte[1024];
            int read;
            while ((read = is.read(buffer)) > 0) {
                md.update(buffer, 0, read);
            }
        } catch (IOException ex) {
            //this is best effort, if we couldn't read the file, assume it's the same
            LOGGER.warn("Error reading file {}", filePath, ex);
            return false;
        }
        byte[] digest = md.digest();
        if (!Arrays.equals(checksum, digest)) {
            //they aren't the same, overwrite old checksum
            System.arraycopy(digest, 0, checksum, 0, digest.length);
            return true;
        }
        return false;
    }
}
