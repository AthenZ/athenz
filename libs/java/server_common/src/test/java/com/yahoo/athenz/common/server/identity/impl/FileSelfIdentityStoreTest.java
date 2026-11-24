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

import com.oath.auth.Utils;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.common.server.util.FilesHelper;
import org.bouncycastle.asn1.x500.X500Name;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

import static org.mockito.ArgumentMatchers.any;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;

public class FileSelfIdentityStoreTest {

    private PrivateKey caKey;
    private X509Certificate caCert;
    private Path identityDir;

    @BeforeClass
    public void setupCA() throws Exception {
        caKey = Crypto.generateRSAPrivateKey(2048);
        final String caCsr = Crypto.generateX509CSR(caKey, "cn=Self Identity Test CA", null);
        caCert = Crypto.generateX509Certificate(Crypto.getPKCS10CertRequest(caCsr), caKey,
                new X500Name("cn=Self Identity Test CA"), 60, true);
    }

    @BeforeMethod
    public void setup() throws IOException {
        identityDir = Files.createTempDirectory("self-identity");
        System.setProperty(FileSelfIdentityStore.PROP_DIR, identityDir.toString());
    }

    @AfterMethod(alwaysRun = true)
    public void cleanup() throws IOException {
        System.clearProperty(FileSelfIdentityStore.PROP_DIR);
        try (Stream<Path> paths = Files.walk(identityDir)) {
            paths.sorted(Comparator.reverseOrder()).map(Path::toFile).forEach(File::delete);
        }
    }

    private X509Certificate issue(PrivateKey key) throws Exception {
        final String csr = Crypto.generateX509CSR(key, "cn=sys.auth.zts", null);
        return Crypto.generateX509Certificate(Crypto.getPKCS10CertRequest(csr), caKey, caCert, 60, false);
    }

    private String readFile(final String fileName) throws IOException {
        return Files.readString(identityDir.resolve(fileName));
    }

    private String permissions(final Path path) throws IOException {
        return PosixFilePermissions.toString(Files.getPosixFilePermissions(path));
    }

    private void assertConsumersCanLoadKey(final String keyAlgorithm, int chainLength) throws Exception {

        final Path keyPath = identityDir.resolve(FileSelfIdentityStore.KEY_FILE_NAME);
        final Path certPath = identityDir.resolve(FileSelfIdentityStore.CERT_FILE_NAME);

        // the provider client ssl context loads the files through the key refresher
        // utils and presents all the certificates in the file as the chain

        KeyStore keyStore = Utils.createKeyStore(certPath.toString(), keyPath.toString());
        final String alias = keyStore.aliases().nextElement();
        assertEquals(keyStore.getCertificateChain(alias).length, chainLength);

        // the roles anywhere credentials provider only accepts unencrypted PKCS#8
        // and parses it with the configured key algorithm

        final String keyPem = Files.readString(keyPath);
        assertTrue(keyPem.startsWith("-----BEGIN PRIVATE KEY-----"));
        final String body = keyPem.replaceAll("-----(BEGIN|END) PRIVATE KEY-----", "").replaceAll("\\s", "");
        KeyFactory.getInstance(keyAlgorithm).generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(body)));
    }

    @Test
    public void testStoreIdentity() throws Exception {

        PrivateKey key = Crypto.generateRSAPrivateKey(2048);
        X509Certificate cert = issue(key);

        // the cert file contains the certificate as returned by the cert signer
        // (here with the intermediate) and the ca file contains the ca bundle

        FileSelfIdentityStore store = (FileSelfIdentityStore) new FileSelfIdentityStoreFactory().create();
        store.storeIdentity(key, List.of(cert, caCert), List.of(caCert));

        assertEquals(readFile(FileSelfIdentityStore.CERT_FILE_NAME),
                Crypto.convertToPEMFormat(cert) + Crypto.convertToPEMFormat(caCert));
        assertEquals(readFile(FileSelfIdentityStore.CA_CERT_FILE_NAME), Crypto.convertToPEMFormat(caCert));
        assertEquals(Crypto.loadPrivateKey(readFile(FileSelfIdentityStore.KEY_FILE_NAME)).getEncoded(),
                key.getEncoded());
        assertConsumersCanLoadKey("RSA", 2);

        assertEquals(permissions(identityDir), "rwx------");
        assertEquals(permissions(identityDir.resolve(FileSelfIdentityStore.KEY_FILE_NAME)), "rw-------");
        assertEquals(permissions(identityDir.resolve(FileSelfIdentityStore.CERT_FILE_NAME)), "rw-r--r--");
        assertEquals(permissions(identityDir.resolve(FileSelfIdentityStore.CA_CERT_FILE_NAME)), "rw-r--r--");

        // a refreshed identity replaces the files

        PrivateKey ecKey = Crypto.generateECPrivateKey("prime256v1");
        X509Certificate ecCert = issue(ecKey);
        store.storeIdentity(ecKey, List.of(ecCert), List.of(caCert));
        assertEquals(readFile(FileSelfIdentityStore.CERT_FILE_NAME), Crypto.convertToPEMFormat(ecCert));
        assertConsumersCanLoadKey("EC", 1);
    }

    @Test
    public void testStoreIdentityWithoutCaCerts() throws Exception {

        PrivateKey key = Crypto.generateRSAPrivateKey(2048);
        X509Certificate cert = issue(key);

        // without any ca certificates the ca file is not written

        FileSelfIdentityStore store = new FileSelfIdentityStore();
        store.storeIdentity(key, List.of(cert), Collections.emptyList());
        store.storeIdentity(key, List.of(cert), null);

        assertEquals(readFile(FileSelfIdentityStore.CERT_FILE_NAME), Crypto.convertToPEMFormat(cert));
        assertFalse(Files.exists(identityDir.resolve(FileSelfIdentityStore.CA_CERT_FILE_NAME)));
    }

    @Test
    public void testCreatesDirectory() throws Exception {

        Path subDir = identityDir.resolve("nested").resolve("identity");
        System.setProperty(FileSelfIdentityStore.PROP_DIR, subDir.toString());

        new FileSelfIdentityStore();
        assertTrue(Files.isDirectory(subDir));
        assertEquals(permissions(subDir), "rwx------");
    }

    @Test
    public void testInvalidDirectory() throws Exception {

        System.clearProperty(FileSelfIdentityStore.PROP_DIR);
        assertCreateFails("missing required property");
        System.setProperty(FileSelfIdentityStore.PROP_DIR, "");
        assertCreateFails("missing required property");

        // the directory cannot be created below a regular file

        Path file = identityDir.resolve("file");
        Files.createFile(file);
        System.setProperty(FileSelfIdentityStore.PROP_DIR, file.resolve("sub").toString());
        assertCreateFails("unable to create directory");

        System.setProperty(FileSelfIdentityStore.PROP_DIR, identityDir.toString());
        FilesHelper filesHelper = Mockito.mock(FilesHelper.class);
        Mockito.when(filesHelper.setPosixFilePermissions(any(), any())).thenThrow(new IOException("permission denied"));
        ServerResourceException ex = expectThrows(ServerResourceException.class,
                () -> new FileSelfIdentityStore(filesHelper));
        assertTrue(ex.getMessage().contains("unable to set permissions"));
    }

    @Test
    public void testStoreIdentityWriteFailure() throws Exception {

        FilesHelper filesHelper = Mockito.mock(FilesHelper.class);
        Mockito.when(filesHelper.move(any(), any())).thenThrow(new IOException("disk full"));
        FileSelfIdentityStore store = new FileSelfIdentityStore(filesHelper);

        PrivateKey key = Crypto.generateRSAPrivateKey(2048);
        X509Certificate cert = issue(key);
        ServerResourceException ex = expectThrows(ServerResourceException.class,
                () -> store.storeIdentity(key, List.of(cert), List.of(caCert)));
        assertTrue(ex.getMessage().contains("unable to write self identity files: disk full"));
        assertEquals(ex.getCode(), ServerResourceException.INTERNAL_SERVER_ERROR);
    }

    private void assertCreateFails(final String message) {
        ServerResourceException ex = expectThrows(ServerResourceException.class, FileSelfIdentityStore::new);
        assertTrue(ex.getMessage().contains(message), ex.getMessage());
        assertEquals(ex.getCode(), ServerResourceException.INTERNAL_SERVER_ERROR);
    }
}
