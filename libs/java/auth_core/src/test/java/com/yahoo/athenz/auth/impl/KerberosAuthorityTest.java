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
package com.yahoo.athenz.auth.impl;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KerberosTicket;

import org.testng.annotations.Test;

import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.token.KerberosToken;

import static com.yahoo.athenz.auth.impl.KerberosAuthority.KRB_PROP_LOGIN_TKT_CACHE_NAME;
import static com.yahoo.athenz.auth.token.KerberosToken.KRB_PROP_TOKEN_PRIV_ACTION;
import static org.testng.Assert.*;
import java.lang.reflect.Field;

public class KerberosAuthorityTest {
    
    private final static String KRB_LOGIN_CB_CLASS = "com.yahoo.athenz.auth.impl.TestLoginCallbackHandler";
    
    @Test(groups="kerberos-tests")
    public void testLoginConfig() {

        KerberosAuthority.LoginConfig loginConfig = new KerberosAuthority.LoginConfig(null, null);
        assertFalse(loginConfig.isDebugEnabled());
        System.setProperty(KRB_PROP_LOGIN_TKT_CACHE_NAME, "testCacheName");
        AppConfigurationEntry[] conf = loginConfig.getAppConfigurationEntry(null);
        AppConfigurationEntry entry = conf[0];
        java.util.Map<String, ?> options = entry.getOptions();
        assertNull(options.get("principal"));
        assertEquals(options.get("useKeyTab"), "false");
        assertEquals(options.get("useTicketCache"), "true");
        assertEquals(options.get("renewTGT"), "true");
        assertNull(options.get("debug"));
        assertEquals(options.get("ticketCache"), "testCacheName");
        System.clearProperty(KRB_PROP_LOGIN_TKT_CACHE_NAME);

        // set properties and remake the login config
        System.setProperty(KerberosAuthority.KRB_PROP_LOGIN_RENEW_TGT, "false");
        System.setProperty(KerberosAuthority.KRB_PROP_LOGIN_USE_TKT_CACHE, "false");
        System.setProperty(KRB_PROP_LOGIN_TKT_CACHE_NAME, "/tmp/cache");
        System.setProperty(KerberosAuthority.KRB_PROP_DEBUG, "TRUE");
        String keyTabConfFile   = "my.keytab";
        String servicePrincipal = "juke";
        loginConfig = new KerberosAuthority.LoginConfig(keyTabConfFile, servicePrincipal);
        assertTrue(loginConfig.isDebugEnabled());
        conf    = loginConfig.getAppConfigurationEntry(null);
        entry   = conf[0];
        options = entry.getOptions();
        assertEquals(options.get("principal"), "juke");
        assertEquals(options.get("useKeyTab"), "true");
        assertEquals(options.get("useTicketCache"), "false");
        assertEquals(options.get("renewTGT"), "false");
        assertEquals(options.get("debug"), "true");
        assertNull(options.get("ticketCache"));
        assertEquals(options.get("keyTab"), "my.keytab");
        System.clearProperty(KerberosAuthority.KRB_PROP_LOGIN_RENEW_TGT);
        System.clearProperty(KerberosAuthority.KRB_PROP_LOGIN_USE_TKT_CACHE);
        System.clearProperty(KRB_PROP_LOGIN_TKT_CACHE_NAME);
        System.clearProperty(KerberosAuthority.KRB_PROP_DEBUG);

    }

    @Test(groups="kerberos-tests")
    public void testKerberosAuthorityBadCreds() {

        KerberosAuthority authority = new KerberosAuthority("myserver@athenz.com",
                "src/test/resources/example.keytab", null);
        authority.initialize();

        assertNull(authority.getDomain());
        assertEquals(authority.getHeader(), KerberosAuthority.KRB_AUTH_HEADER);

        KerberosToken token;
        String creds        = "invalid_creds";
        String remoteAddr   = "some.address";
        try {
            new KerberosToken(creds, remoteAddr);
            fail("new KerberosToken with bad creds");
        } catch (IllegalArgumentException exc) {
            String msg = exc.getMessage();
            assertTrue(msg.contains("creds do not contain required Negotiate component"));
        }

        creds = KerberosToken.KRB_AUTH_VAL_FLD + " YIGeBgYrBgEFBQKggZMwgZCgGjAYBgorBgEEAYI3AgIeBgorBgEEAYI3AgIKonIEcE5FR09FWFRTAAfakecreds";
        token = new KerberosToken(creds, remoteAddr);

        StringBuilder errMsg = new StringBuilder();
        Principal principal  = authority.authenticate(token.getSignedToken(), null, "GET", errMsg);
        assertNull(principal);
    }

    @Test(groups="kerberos-tests")
    public void testKerberosAuthorityMockPrivExcAction() {

        System.setProperty(KRB_PROP_TOKEN_PRIV_ACTION, "com.yahoo.athenz.auth.impl.MockPrivExcAction");
        System.setProperty(KRB_PROP_TOKEN_PRIV_ACTION + "_TEST_REALM", "USER_REALM");
        String token = "YWJjdGVzdA==";
        System.setProperty(KerberosAuthority.KRB_PROP_SVCPRPL, "myserver@EXAMPLE.COM");
        System.setProperty(KerberosAuthority.KRB_PROP_LOGIN_CB_CLASS, KRB_LOGIN_CB_CLASS);
        System.setProperty(KerberosAuthority.KRB_PROP_KEYTAB, "src/test/resources/example.keytab");
        
        KerberosAuthority authority = new KerberosAuthority();
        authority.initialize();

        String creds = KerberosToken.KRB_AUTH_VAL_FLD + " " + token;
        String remoteAddr = "localhost";
        KerberosToken ktoken = new KerberosToken(creds, remoteAddr);
        boolean ret = ktoken.validate(null, null);
        assertTrue(ret);

        StringBuilder errMsg = new StringBuilder();
        Principal principal  = authority.authenticate(ktoken.getSignedToken(), null, "GET", errMsg);
        assertNotNull(principal);
        assertNotNull(principal.getAuthority());
        assertEquals(principal.getCredentials(), ktoken.getSignedToken());
        assertEquals(principal.getDomain(), ktoken.getDomain());
        assertEquals(principal.getDomain(), KerberosToken.USER_DOMAIN);
        assertEquals(principal.getName(), ktoken.getUserName());
        assertEquals(principal.getName().indexOf('@'), -1);
        
        principal = authority.authenticate(ktoken.getSignedToken(), null, "GET", null);
        assertNotNull(principal);

        // test with ygrid realm
        System.setProperty(KRB_PROP_TOKEN_PRIV_ACTION + "_TEST_REALM", KerberosToken.KRB_USER_REALM);
        ktoken = new KerberosToken(creds, remoteAddr);
        ret = ktoken.validate(null, null);
        assertTrue(ret);

        errMsg = new StringBuilder();
        principal  = authority.authenticate(ktoken.getSignedToken(), null, "GET", errMsg);
        assertNotNull(principal);
        assertNotNull(principal.getAuthority());
        assertEquals(principal.getCredentials(), ktoken.getSignedToken());
        assertEquals(principal.getDomain(), ktoken.getDomain());
        assertEquals(principal.getDomain(), KerberosToken.KRB_USER_DOMAIN);
        assertEquals(principal.getName(), ktoken.getUserName());
        assertEquals(principal.getName().indexOf('@'), -1);
        
        principal = authority.authenticate(ktoken.getSignedToken(), null, "GET", null);
        assertNotNull(principal);

        // test with invalid realm
        System.setProperty(KRB_PROP_TOKEN_PRIV_ACTION + "_TEST_REALM", "REALM.SOMECOMPANY.COM");
        ktoken = new KerberosToken(creds, remoteAddr);
        ret = ktoken.validate(null, null);
        assertFalse(ret);

        errMsg = new StringBuilder();
        principal  = authority.authenticate(ktoken.getSignedToken(), null, "GET", errMsg);
        assertNull(principal);
        
        principal = authority.authenticate(ktoken.getSignedToken(), null, "GET", null);
        assertNull(principal);
        
        principal = authority.authenticate(null, null, "GET", null);
        assertNull(principal);

        principal = authority.authenticate(null, null, "GET", errMsg);
        assertNull(principal);

        System.clearProperty(KRB_PROP_TOKEN_PRIV_ACTION);
        System.clearProperty(KerberosAuthority.KRB_PROP_SVCPRPL);
        System.clearProperty(KerberosAuthority.KRB_PROP_LOGIN_CB_CLASS);
        System.clearProperty(KerberosAuthority.KRB_PROP_KEYTAB);
    }

    @Test(groups="kerberos-tests")
    public void testKerberosAuthorityJaas() {
        
        System.setProperty("java.security.auth.login.config", "src/test/resources/jaas.conf");
        System.setProperty("java.security.krb5.kdc", "localhost");
        System.setProperty( "sun.security.krb5.debug", "true");
        System.setProperty( "javax.security.auth.useSubjectCredsOnly", "true");
        System.setProperty(KerberosAuthority.KRB_PROP_JAASCFG, "Server");
        System.setProperty(KerberosAuthority.KRB_PROP_LOGIN_CB_CLASS, KRB_LOGIN_CB_CLASS);
        
        KerberosAuthority kauth = new KerberosAuthority();
        kauth.initialize();
        Exception initState = kauth.getInitState();
        assertNotNull(initState);
        assertTrue(initState instanceof javax.security.auth.login.LoginException);
        
        System.clearProperty("java.security.auth.login.config");
        System.clearProperty("java.security.krb5.kdc");
        System.clearProperty("sun.security.krb5.debug");
        System.clearProperty("javax.security.auth.useSubjectCredsOnly");
        System.clearProperty(KerberosAuthority.KRB_PROP_JAASCFG);
        System.clearProperty(KerberosAuthority.KRB_PROP_LOGIN_CB_CLASS);
    }
    
    @Test(groups="kerberos-tests")
    public void testKerberosAuthorityKeytab() {
        
        System.setProperty(KerberosAuthority.KRB_PROP_KEYTAB, "src/test/resources/example.keytab");
        System.setProperty(KerberosAuthority.KRB_PROP_SVCPRPL, "myserver@EXAMPLE.COM");
        System.setProperty(KerberosAuthority.KRB_PROP_LOGIN_CB_CLASS, KRB_LOGIN_CB_CLASS);
        System.setProperty( "sun.security.krb5.debug", "true");
        System.setProperty( "java.security.krb5.realm", "EXAMPLE.COM");
        System.setProperty( "java.security.krb5.kdc", "localhost");
        
        KerberosAuthority kauth = new KerberosAuthority();
        kauth.initialize();
        assertEquals("Auth-KERB", kauth.getID());

        Exception initState = kauth.getInitState();
        assertNull(initState);
        
        System.clearProperty(KerberosAuthority.KRB_PROP_KEYTAB);
        System.clearProperty(KerberosAuthority.KRB_PROP_SVCPRPL);
        System.clearProperty(KerberosAuthority.KRB_PROP_LOGIN_CB_CLASS);
        System.clearProperty( "java.security.krb5.realm");
        System.clearProperty( "java.security.krb5.kdc");
    }

    @Test(groups="kerberos-tests")
    public void testKerberosAuthorityIsOurPrincipal() {
        System.setProperty(KerberosAuthority.KRB_PROP_KEYTAB, "src/test/resources/example.keytab");
        System.setProperty(KerberosAuthority.KRB_PROP_SVCPRPL, "myserver@EXAMPLE.COM");
        System.setProperty(KerberosAuthority.KRB_PROP_LOGIN_CB_CLASS, KRB_LOGIN_CB_CLASS);
        System.setProperty( "sun.security.krb5.debug", "true");
 
        KerberosAuthority kauth = new KerberosAuthority();
        kauth.initialize();
        Exception initState = kauth.getInitState();
        assertNull(initState);

        KerberosPrincipal princ = new KerberosPrincipal("myserver@EXAMPLE.COM");
        String token = "YIIB6wYJKoZIhvcSAQICAQBuggHaMIIB1qADAgEFoQMCAQ6iBwMFAAAAAACjggEGYYIBAjCB/6ADAgEFoQ0bC0VYQU1QTEUuQ09NojAwLqADAgEAoScwJRsHZGF0YWh1YhsTZGF0YWh1Yi5leGFtcGxlLmNvbRsFYnVsbHmjgbYwgbOgAwIBA6KBqwSBqMJGf4H5nrRIdDyNxHp5fwxW6lsiFi+qUjryPvgiOAl/XldfwmKd9wXbQn00VBNhK+oVxmKv0V0J80e4oTdUnc+NlU/BJNCfsLPFTdYntc4A/ffdnsY7/U5HktTaWMfhvWxYocvhqISFTIFUT1+pH5742IWYNTgvFd5vkudibB3ijCanbMYv9CQXEjV+380rnf3gdLD2JGuxmaU78aJjDDKETL6Ck/qz8KSBtjCBs6ADAgEDooGrBIGoMrzLCTUi59wEoWX02+42K5m1MzW6HMNSuvfQeVGJdzPBsiFmZweNfJF6L9LdmLjQR4jSVUhVo3neFZmUN8G532wvZeKbHOtkXTnLRRdif+DoKyI8GOkbHu1CZlevcQZ0sgzyiH0wfQ/0nguE4kH7a2bM7HlV7N6MRGkC4DDkJZDNHxQr27FbZqrqEyw498HXPTtF93JGsKjXB8Z/wDaPs4PpdfoThTol";
        byte[] asn1Encoding = token.getBytes();
        byte[] sessionKey   = "xyz".getBytes();
        long endMillis = System.currentTimeMillis() + 2000;
        java.util.Date endDate = new java.util.Date();
        endDate.setTime(endMillis);
        KerberosTicket ticket = new KerberosTicket(asn1Encoding, princ, princ, sessionKey, 0, null, null, null, endDate, null, null);

        boolean ours = kauth.isTargetPrincipal(ticket, "myserver@EXAMPLE.COM");
        assertTrue(ours);

        KerberosPrincipal clientPrinc = new KerberosPrincipal("myclient@EXAMPLE.COM");
        ticket = new KerberosTicket(asn1Encoding, princ, clientPrinc, sessionKey, 0, null, null, null, endDate, null, null);

        ours = kauth.isTargetPrincipal(ticket, "myservice@EXAPLE.COM");
        assertFalse(ours);

        System.clearProperty(KerberosAuthority.KRB_PROP_SVCPRPL);
        System.clearProperty(KerberosAuthority.KRB_PROP_KEYTAB);
        System.clearProperty(KerberosAuthority.KRB_PROP_LOGIN_CB_CLASS);
    }

    @Test(groups="kerberos-tests")
    public void testKerberosAuthorityLogin() {

        System.setProperty(KerberosAuthority.KRB_PROP_LOGIN_WINDOW, "1000");
        System.setProperty(KerberosAuthority.KRB_PROP_KEYTAB, "src/test/resources/example.keytab");
        System.setProperty(KerberosAuthority.KRB_PROP_SVCPRPL, "myserver@EXAMPLE.COM");
        System.setProperty(KerberosAuthority.KRB_PROP_LOGIN_CB_CLASS, KRB_LOGIN_CB_CLASS);
        System.setProperty( "sun.security.krb5.debug", "true");
 
        KerberosAuthority kauth = new KerberosAuthority();
        kauth.initialize();
        Exception initState = kauth.getInitState();
        assertNull(initState);

        kauth.login(false);
        initState = kauth.getInitState();
        assertNull(initState);

        try {
            Thread.sleep(2000);
        } catch (Exception exc) {
            System.out.println("testKerberosAuthorityLogin: sleep failed: continuing...");
        }

        kauth.login(true);
        initState = kauth.getInitState();
        assertTrue(initState == null || initState instanceof javax.security.auth.login.LoginException);

        System.clearProperty(KerberosAuthority.KRB_PROP_LOGIN_WINDOW);
        System.clearProperty(KerberosAuthority.KRB_PROP_SVCPRPL);
        System.clearProperty(KerberosAuthority.KRB_PROP_KEYTAB);
        System.clearProperty(KerberosAuthority.KRB_PROP_LOGIN_CB_CLASS);
    }

    @Test(groups="kerberos-tests")
    public void testKerberosAuthorityRefreshLogin() {
        System.setProperty(KerberosAuthority.KRB_PROP_LOGIN_WINDOW, "1000");
        System.setProperty(KerberosAuthority.KRB_PROP_KEYTAB, "src/test/resources/example.keytab");
        System.setProperty(KerberosAuthority.KRB_PROP_SVCPRPL, "myserver@EXAMPLE.COM");
        System.setProperty(KerberosAuthority.KRB_PROP_LOGIN_CB_CLASS, KRB_LOGIN_CB_CLASS);
        System.setProperty("sun.security.krb5.debug", "true");
 
        KerberosAuthority kauth = new KerberosAuthority();
        kauth.initialize();
        Exception initState = kauth.getInitState();
        assertNull(initState);

        long lastLogin = kauth.getLastLogin();
        long now       = System.currentTimeMillis();
        assertTrue(lastLogin <= now);

        long loginWindow = kauth.getLoginWindow();
        assertEquals(loginWindow, 1000);

        boolean refreshed = kauth.refreshLogin("myserver@EXAMPLE.COM");
        assertTrue(refreshed);
        initState = kauth.getInitState();
        assertNull(initState);

        try {
            Thread.sleep(2000);
        } catch (Exception exc) {
            System.out.println("testKerberosAuthorityLogin: sleep failed: continuing...");
        }

        refreshed = kauth.refreshLogin("myserver@EXAMPLE.COM");
        assertTrue(refreshed);
        initState = kauth.getInitState();
        assertNull(initState);

        System.clearProperty(KerberosAuthority.KRB_PROP_LOGIN_WINDOW);
        System.clearProperty(KerberosAuthority.KRB_PROP_SVCPRPL);
        System.clearProperty(KerberosAuthority.KRB_PROP_KEYTAB);
        System.clearProperty(KerberosAuthority.KRB_PROP_LOGIN_CB_CLASS);
    }

    @Test(groups="kerberos-tests")
    public void testSetInitState() throws NoSuchFieldException, SecurityException,
            IllegalArgumentException, IllegalAccessException {
        Class<KerberosAuthority> c = KerberosAuthority.class;
        KerberosAuthority check  = new KerberosAuthority();

        check.setInitState(null);
        
        Field f = c.getDeclaredField("initState");
        f.setAccessible(true);
        Exception m = (Exception) f.get(check);
        
        assertNull(m);
    }

    @Test(groups="kerberos-tests")
    public void testSetLoginWindow() throws NoSuchFieldException, SecurityException,
            IllegalArgumentException, IllegalAccessException {
        Class<KerberosAuthority> c = KerberosAuthority.class;
        KerberosAuthority check  = new KerberosAuthority();
        
        check.setLoginWindow((long)100);
        
        Field f = c.getDeclaredField("loginWindow");
        f.setAccessible(true);
        long m = (long) f.get(check);
        
        assertEquals(m,100);
    }

    @Test(groups="kerberos-tests")
    public void testIsTargetPrincipalIlligal() {
        KerberosAuthority check  = new KerberosAuthority();

        assertFalse(check.isTargetPrincipal(null,null));
    }

    @Test
    public void testGetAuthenticateChallenge() {
        KerberosAuthority krbAuthority  = new KerberosAuthority();
        assertEquals(krbAuthority.getAuthenticateChallenge(), "Negotiate");
    }

    @Test
    public void testKerberosAuthorityNullParametrs() {
        KerberosAuthority kerbesrosAuthority = new KerberosAuthority(null, null, "jaas.conf");
        assertNotNull(kerbesrosAuthority);
    }

    @Test
    public void testKerberosToken() {
        System.clearProperty(KRB_PROP_TOKEN_PRIV_ACTION);
        System.setProperty(KRB_PROP_TOKEN_PRIV_ACTION + "_TEST_REALM", "USER_REALM");
        String token = "YWJjdGVzdA==";
        System.setProperty(KerberosAuthority.KRB_PROP_SVCPRPL, "myserver@EXAMPLE.COM");
        System.setProperty(KerberosAuthority.KRB_PROP_LOGIN_CB_CLASS, KRB_LOGIN_CB_CLASS);
        System.setProperty(KerberosAuthority.KRB_PROP_KEYTAB, "src/test/resources/example.keytab");

        KerberosAuthority authority = new KerberosAuthority();
        authority.initialize();

        String creds = KerberosToken.KRB_AUTH_VAL_FLD + " " + token;
        String remoteAddr = "localhost";
        KerberosToken ktoken = new KerberosToken(creds, remoteAddr);
        boolean ret = ktoken.validate(null, null);
        assertFalse(ret);
        StringBuilder errMsg = new StringBuilder();
        ret = ktoken.validate(null, errMsg);
        assertFalse(ret);
    }
}
