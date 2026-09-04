package com.yahoo.athenz.zpe.pkey.file;

import com.yahoo.athenz.zms.PublicKeyEntry;
import com.yahoo.athenz.zpe.pkey.PublicKeyStore;
import com.yahoo.athenz.zts.JWK;
import com.yahoo.rdl.JSON;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import static com.yahoo.athenz.auth.util.Crypto.convertToPEMFormat;
import static com.yahoo.athenz.zpe.ZpeConsts.ZPE_PROP_ATHENZ_CONF;
import static com.yahoo.athenz.zpe.ZpeConsts.ZPE_PROP_JWK_ATHENZ_CONF;
import static org.testng.Assert.*;

public class FilePublicKeyStoreTest {

    // the athenz conf settings are configured for the whole jvm and other
    // test classes in this module rely on them, so we must save and restore
    // the original values instead of just clearing them

    private String savedAthenzConf;
    private String savedJwkAthenzConf;

    @BeforeClass
    public void setUp() {
        savedAthenzConf = System.getProperty(ZPE_PROP_ATHENZ_CONF);
        savedJwkAthenzConf = System.getProperty(ZPE_PROP_JWK_ATHENZ_CONF);
        System.setProperty(ZPE_PROP_JWK_ATHENZ_CONF, FilePublicKeyStoreTest.class.getClassLoader().getResource("jwk/athenz.conf").getPath());
    }

    @AfterClass
    public void tearDown() {
        restoreProperty(ZPE_PROP_ATHENZ_CONF, savedAthenzConf);
        restoreProperty(ZPE_PROP_JWK_ATHENZ_CONF, savedJwkAthenzConf);
    }

    private void restoreProperty(final String propName, final String propValue) {
        if (propValue == null) {
            System.clearProperty(propName);
        } else {
            System.setProperty(propName, propValue);
        }
    }

    @Test
    public void testLoadFilePublicKeyStore() {
        System.setProperty(ZPE_PROP_ATHENZ_CONF, FilePublicKeyStoreTest.class.getClassLoader().getResource("athenz.conf").getPath());
        
        FilePublicKeyStoreFactory factory = new FilePublicKeyStoreFactory();
        PublicKeyStore publicKeyStore = factory.create();
        
        assertNotNull(publicKeyStore.getZmsKey("0"));
        assertNotNull(publicKeyStore.getZmsKey("1"));
        assertNotNull(publicKeyStore.getZmsKey("2"));
        assertNull(publicKeyStore.getZmsKey("3"));
        assertNotNull(publicKeyStore.getZmsKey("FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ"));
        

        assertNotNull(publicKeyStore.getZtsKey("0"));
        assertNotNull(publicKeyStore.getZtsKey("1"));
        assertNotNull(publicKeyStore.getZtsKey("2"));
        assertNull(publicKeyStore.getZtsKey("3"));
        assertNotNull(publicKeyStore.getZtsKey("c6e34b18-fb1c-43bb-9de7-7edc8981b14d"));

        restoreProperty(ZPE_PROP_ATHENZ_CONF, savedAthenzConf);
    }
    
    
    @Test
    public void testReloadAthenzJwkConf() throws InterruptedException {
        FilePublicKeyStoreFactory factory = new FilePublicKeyStoreFactory();
        PublicKeyStore publicKeyStore = factory.create();

        assertNotNull(publicKeyStore.getZmsKey("FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ"));
        assertNotNull(publicKeyStore.getZtsKey("c6e34b18-fb1c-43bb-9de7-7edc8981b14d"));
        assertNull(publicKeyStore.getZtsKey("new-key"));
        
        // load new jwk config file
        Thread.sleep(1);
        ((FilePublicKeyStore) publicKeyStore).millisBetweenReloadAthenzConfig = 0;
        System.setProperty(ZPE_PROP_JWK_ATHENZ_CONF, FilePublicKeyStoreTest.class.getClassLoader().getResource("jwk/athenz.conf.new").getPath());
        assertNotNull(publicKeyStore.getZtsKey("new-key"));
        assertNull(publicKeyStore.getZmsKey(null));
        assertNull(publicKeyStore.getZtsKey(null));
    }

    @Test
    public void testRSAJwkToPubKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidParameterSpecException {
        Path jwkPath = Paths.get(FilePublicKeyStoreTest.class.getClassLoader().getResource("jwk/rsa.pub.jwk").getPath());
        JWK jwk = JSON.fromBytes(Files.readAllBytes(jwkPath), JWK.class);
        PublicKey pKey = new FilePublicKeyStore().jwkToPubKey(jwk);

        Path pemPath = Paths.get(FilePublicKeyStoreTest.class.getClassLoader().getResource("jwk/rsa.pub.pem").getPath());
        assertEquals(convertToPEMFormat(pKey), new String((Files.readAllBytes(pemPath))));
    }

    @Test
    public void testECJwkToPubKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidParameterSpecException {
        Path jwkPath = Paths.get(FilePublicKeyStoreTest.class.getClassLoader().getResource("jwk/ec.pub.jwk").getPath());
        JWK jwk = JSON.fromBytes(Files.readAllBytes(jwkPath), JWK.class);
        PublicKey pKey = new FilePublicKeyStore().jwkToPubKey(jwk);

        Path pemPath = Paths.get(FilePublicKeyStoreTest.class.getClassLoader().getResource("jwk/ec.pub.pem").getPath());
        assertEquals(convertToPEMFormat(pKey), new String((Files.readAllBytes(pemPath))));
    }

    @Test
    public void testCanReload() throws InterruptedException {
        FilePublicKeyStoreFactory factory = new FilePublicKeyStoreFactory();
        FilePublicKeyStore filePubKeyStore = (FilePublicKeyStore) factory.create();
        assertFalse(filePubKeyStore.canReloadAthenzConfig());
        filePubKeyStore.millisBetweenReloadAthenzConfig = 0;
        Thread.sleep(1);
        assertTrue(filePubKeyStore.canReloadAthenzConfig());
    }

    @Test
    public void testLoadPublicKeysInvalidEntries() {

        FilePublicKeyStore publicKeyStore = new FilePublicKeyStore();
        Map<String, PublicKey> keyMap = new HashMap<>();

        // null list of keys must be handled without any exceptions

        publicKeyStore.loadPublicKeys(null, keyMap);
        assertTrue(keyMap.isEmpty());

        // entries with missing id or key are skipped, and entries with
        // invalid key data are skipped as well

        ArrayList<PublicKeyEntry> publicKeys = new ArrayList<>();
        publicKeys.add(new PublicKeyEntry().setId("no-key"));
        publicKeys.add(new PublicKeyEntry().setKey("bm8taWQ-"));
        publicKeys.add(new PublicKeyEntry().setId("invalid-key").setKey("aW52YWxpZC1rZXk-"));

        publicKeyStore.loadPublicKeys(publicKeys, keyMap);
        assertTrue(keyMap.isEmpty());
    }

    @Test
    public void testInitInvalidConfigFiles() {

        // configure both config files to point to non-existent files
        // so that the public key store ends up with no keys at all

        System.setProperty(ZPE_PROP_ATHENZ_CONF, "src/test/resources/athenz_not_found.conf");
        System.setProperty(ZPE_PROP_JWK_ATHENZ_CONF, "src/test/resources/jwk/athenz_not_found.conf");

        try {
            FilePublicKeyStore publicKeyStore = new FilePublicKeyStore();
            publicKeyStore.init();

            assertNull(publicKeyStore.getZtsKey("0"));
            assertNull(publicKeyStore.getZmsKey("0"));
            assertNull(publicKeyStore.getZtsKey("c6e34b18-fb1c-43bb-9de7-7edc8981b14d"));
            assertNull(publicKeyStore.getZmsKey("FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ"));
        } finally {
            restoreProperty(ZPE_PROP_ATHENZ_CONF, savedAthenzConf);
            System.setProperty(ZPE_PROP_JWK_ATHENZ_CONF, FilePublicKeyStoreTest.class.getClassLoader().getResource("jwk/athenz.conf").getPath());
        }
    }

    @Test
    public void testInitInvalidJwkKeyType() {

        // the jwk config file includes a zms key with an unsupported
        // key type which must be skipped while the valid zts key
        // must still be loaded

        System.setProperty(ZPE_PROP_ATHENZ_CONF, "src/test/resources/athenz_not_found.conf");
        System.setProperty(ZPE_PROP_JWK_ATHENZ_CONF, FilePublicKeyStoreTest.class.getClassLoader().getResource("jwk/athenz_invalid_key.conf").getPath());

        try {
            FilePublicKeyStore publicKeyStore = new FilePublicKeyStore();
            publicKeyStore.init();

            assertNull(publicKeyStore.getZmsKey("unsupported-key-type"));
            assertNotNull(publicKeyStore.getZtsKey("c6e34b18-fb1c-43bb-9de7-7edc8981b14d"));
        } finally {
            restoreProperty(ZPE_PROP_ATHENZ_CONF, savedAthenzConf);
            System.setProperty(ZPE_PROP_JWK_ATHENZ_CONF, FilePublicKeyStoreTest.class.getClassLoader().getResource("jwk/athenz.conf").getPath());
        }
    }
}