package com.yahoo.athenz.zpe.pkey.file;

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

import static com.yahoo.athenz.auth.util.Crypto.convertToPEMFormat;
import static com.yahoo.athenz.zpe.ZpeConsts.ZPE_PROP_ATHENZ_CONF;
import static com.yahoo.athenz.zpe.ZpeConsts.ZPE_PROP_JWK_ATHENZ_CONF;
import static org.testng.Assert.assertFalse;
import static org.testng.AssertJUnit.*;

public class FilePublicKeyStoreTest {

    @BeforeClass
    public void setUp() {
        System.setProperty(ZPE_PROP_JWK_ATHENZ_CONF, FilePublicKeyStoreTest.class.getClassLoader().getResource("jwk/athenz.conf").getPath());
    }
    
    @AfterClass
    public void tearDown() {
        System.clearProperty(ZPE_PROP_JWK_ATHENZ_CONF);
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
        
        System.clearProperty(ZPE_PROP_ATHENZ_CONF);
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
    
}