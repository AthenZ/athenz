/*
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.common.server.identity.impl;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.common.server.identity.SelfIdentityStore;
import com.yahoo.athenz.common.server.util.FilesHelper;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.attribute.PosixFilePermission;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * Writes the server's self identity as PEM files into a configured
 * directory so that other components can load them through their
 * existing file path settings:
 *   zts.key.pem  - unencrypted PKCS#8 private key (mode 0600)
 *   zts.cert.pem - certificate as returned by the cert signer (the leaf
 *                  certificate optionally followed by its intermediates)
 *   ca.cert.pem  - CA certificate bundle (only if available)
 * Each file is replaced atomically.
 */
public class FileSelfIdentityStore implements SelfIdentityStore {

    private static final Logger LOGGER = LoggerFactory.getLogger(FileSelfIdentityStore.class);

    static final String PROP_DIR = "athenz.zts.self_identity.dir";

    static final String KEY_FILE_NAME     = "zts.key.pem";
    static final String CERT_FILE_NAME    = "zts.cert.pem";
    static final String CA_CERT_FILE_NAME = "ca.cert.pem";

    private static final Set<PosixFilePermission> DIR_PERMISSIONS = EnumSet.of(PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE);
    private static final Set<PosixFilePermission> PRIVATE_FILE_PERMISSIONS = EnumSet.of(
            PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
    private static final Set<PosixFilePermission> PUBLIC_FILE_PERMISSIONS = EnumSet.of(
            PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
            PosixFilePermission.GROUP_READ, PosixFilePermission.OTHERS_READ);

    final File identityDir;
    final FilesHelper filesHelper;

    public FileSelfIdentityStore() throws ServerResourceException {
        this(new FilesHelper());
    }

    FileSelfIdentityStore(FilesHelper filesHelper) throws ServerResourceException {

        final String dir = System.getProperty(PROP_DIR);
        if (dir == null || dir.isEmpty()) {
            throw error("missing required property: " + PROP_DIR);
        }
        this.identityDir = new File(dir);
        this.filesHelper = filesHelper;

        if (!identityDir.exists() && !identityDir.mkdirs()) {
            throw error("unable to create directory: " + identityDir.getPath());
        }
        try {
            filesHelper.setPosixFilePermissions(identityDir, DIR_PERMISSIONS);
        } catch (IOException ex) {
            throw error("unable to set permissions on directory " + identityDir.getPath() + ": " + ex.getMessage());
        }
    }

    @Override
    public void storeIdentity(PrivateKey privateKey, List<X509Certificate> certificateChain,
            List<X509Certificate> caCertificates) throws ServerResourceException {

        try {
            writeFile(KEY_FILE_NAME, toPkcs8Pem(privateKey), PRIVATE_FILE_PERMISSIONS);
            writeFile(CERT_FILE_NAME, toPem(certificateChain), PUBLIC_FILE_PERMISSIONS);
            if (caCertificates != null && !caCertificates.isEmpty()) {
                writeFile(CA_CERT_FILE_NAME, toPem(caCertificates), PUBLIC_FILE_PERMISSIONS);
            }
        } catch (IOException ex) {
            throw error("unable to write self identity files: " + ex.getMessage());
        }
    }

    String toPem(List<X509Certificate> certificates) {
        return Crypto.x509CertificatesToPEM(certificates.toArray(new X509Certificate[0]));
    }

    String toPkcs8Pem(PrivateKey privateKey) throws IOException {

        // write the key in unencrypted PKCS#8 format since some consumers
        // (e.g. the IAM Roles Anywhere credentials provider) only support it

        StringWriter writer = new StringWriter();
        try (PemWriter pemWriter = new PemWriter(writer)) {
            pemWriter.writeObject(new PemObject("PRIVATE KEY", privateKey.getEncoded()));
        }
        return writer.toString();
    }

    void writeFile(final String fileName, final String data, Set<PosixFilePermission> perms) throws IOException {

        // write into a temporary file with the final permissions first and
        // then atomically replace the target so readers never see partial data

        final File tempFile = new File(identityDir, "." + fileName + ".tmp");
        filesHelper.createEmptyFile(tempFile);
        filesHelper.setPosixFilePermissions(tempFile, perms);
        filesHelper.write(tempFile, data.getBytes(StandardCharsets.UTF_8));
        filesHelper.move(tempFile, new File(identityDir, fileName));
    }

    private static ServerResourceException error(final String message) {
        LOGGER.error("FileSelfIdentityStore: {}", message);
        return new ServerResourceException(ServerResourceException.INTERNAL_SERVER_ERROR, message);
    }
}
