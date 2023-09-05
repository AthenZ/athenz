package com.yahoo.athenz.common.config;

import static org.testng.Assert.*;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.ArrayList;

import com.yahoo.athenz.zms.PublicKeyEntry;

public class AthenzConfigTest {
    
    AthenzConfig chk_config = new AthenzConfig();
    
    @Mock
    ArrayList<PublicKeyEntry> chk_zmsPubkey;
    @Mock
    ArrayList<PublicKeyEntry> chk_ztsPubkey;
    
    @BeforeMethod
    public void setUp(){
        MockitoAnnotations.openMocks(this);
    }
    
    @Test
    public void testZmsUrl(){
        String chk_zmsUrl = "check_zmsUrl";
        
        chk_config.setZmsUrl(chk_zmsUrl);
        
        String check = chk_config.getZmsUrl();
        assertNotNull(check);
        assertEquals(check,"check_zmsUrl");
    }
    
    @Test
    public void testZtsUrl(){
        String chk_ztsUrl = "check_ztsUrl";
        
        chk_config.setZtsUrl(chk_ztsUrl);
        
        String check = chk_config.getZtsUrl();
        assertNotNull(check);
        assertEquals(check,"check_ztsUrl");
    }
    
    @Test
    public void testZmsPrivateKey() {
        chk_config.setZmsPublicKeys(chk_zmsPubkey);
        
        ArrayList<PublicKeyEntry> check = chk_config.getZmsPublicKeys();
        assertNotNull(check);
    }
    
    @Test
    public void testZtsPrivateKey() {
        chk_config.setZtsPublicKeys(chk_ztsPubkey);
        
        ArrayList<PublicKeyEntry> check = chk_config.getZtsPublicKeys();
        assertNotNull(check);
    }
}
