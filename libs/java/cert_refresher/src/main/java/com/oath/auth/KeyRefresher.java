package com.oath.auth;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class KeyRefresher {

    private Thread scanForFileChangesThread;
    private boolean shutdown = false; //only for testing
    //60 seconds * 60 (min in an hour)
    private static final int RETRY_CHECK_FREQUENCY = 60_000 * 60;

    private final MessageDigest md;
    private byte[] lastPublicKeyManagerChecksum = new byte[0]; //initialize to empty to avoid NPE
    private byte[] lastPrivateKeyManagerChecksum = new byte[0]; //initialize to empty to avoid NPE
    private byte[] lastTrustManagerChecksum = new byte[0]; //initialize to empty to avoid NPW


    private final String athensPublicKey;
    private final String athensPrivateKey;
    private final String trustStorePath;
    private final KeyManagerProxy keyManagerProxy;
    private final TrustManagerProxy trustManagerProxy;

    /**
     * this method should be invoked primarily by the Utils.generateKeyRefresher method
     *
     * Once created, it needs to be turned on using the startup() method.  It will then
     * wake up once an hour and check the various public/private keys and trust store files
     * to see if they have been updated.  If so, it will automatically update the SSL context
     * correlating to the client/server that the *ManagerProxy objects are tied to.
     *
     * If you want to stop this thread, you need to call the shutdown() method
     *
     * @param athensPublicKey the file path to this key
     * @param athensPrivateKey the file path to this key
     * @param trustStorePath the file path to this store
     * @param keyManagerProxy the keyManagerProxy used in the existing server/client
     * @param trustManagerProxy the keyManagerProxy used in the existing server/client
     * @throws NoSuchAlgorithmException this is only thrown if we cannot use MD5 hashing
     */
    public KeyRefresher(final String athensPublicKey, final String athensPrivateKey, final String trustStorePath,
                        final KeyManagerProxy keyManagerProxy, final TrustManagerProxy trustManagerProxy) throws NoSuchAlgorithmException {
        this.athensPublicKey = athensPublicKey;
        this.athensPrivateKey = athensPrivateKey;
        this.trustStorePath = trustStorePath;
        this.keyManagerProxy = keyManagerProxy;
        this.trustManagerProxy = trustManagerProxy;
        md = MessageDigest.getInstance("MD5");
    }

    public KeyManagerProxy getKeyManagerProxy() {
        return keyManagerProxy;
    }

    public TrustManagerProxy getTrustManagerProxy() {
        return trustManagerProxy;
    }

    private void scanForFileChanges() {
        scanForFileChangesThread = new Thread(() -> {
            // run loop contents here
            while (!shutdown) {
                try {
                    if (haveFilesBeenChanged(trustStorePath, lastTrustManagerChecksum)) {
                        trustManagerProxy.setTrustManager(Utils.getTrustManagers(trustStorePath));
                    }
                    //we want to check both files (public + private) and update both checksums
                    boolean keyFilesChanged = haveFilesBeenChanged(athensPrivateKey, lastPrivateKeyManagerChecksum);
                    keyFilesChanged = haveFilesBeenChanged(athensPublicKey, lastPublicKeyManagerChecksum) || keyFilesChanged;
                    if (keyFilesChanged) {
                        keyManagerProxy.setKeyManager(Utils.getKeyManagers(athensPublicKey, athensPrivateKey));
                    }
                } catch (Exception ignored) {
                    // if we could not reload the SSL context (but we tried) we will ignore it and hope it works on the next loop
                } try {
                    Thread.sleep(RETRY_CHECK_FREQUENCY);
                } catch (InterruptedException ignored) { }
            }
        });
        scanForFileChangesThread.setDaemon(true);
        scanForFileChangesThread.setName("scanForFileChanges" + " started at:" + System.currentTimeMillis());
        scanForFileChangesThread.start();
    }


    public void shutdown() {
        shutdown = true;
    }

    public void startup() {
        shutdown = false;
        scanForFileChanges();
    }

    /**
     *  If the checksum for the file has changed, then update the checksum and return true.  else return false
     */
    protected boolean haveFilesBeenChanged(final String filePath, byte[] checksum) {
        try (InputStream is = Files.newInputStream(Paths.get(filePath));
             DigestInputStream digestInputStream = new DigestInputStream(is, md)) {
            while (digestInputStream.read() != -1) {
                ; // do nothing, just read until the EoF
            }
        } catch (IOException ignored) {
            //this is best effort, if we couldnt read the file, assume its the same
            return false;
        }
        byte[] digest = md.digest();
        if (!Arrays.equals(checksum, digest)) {
            //they arent the same, overwrite old checksum
            checksum = digest;
            return true;
        }
        return false;
    }

}
