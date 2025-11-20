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
package com.yahoo.athenz.zts.token;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.yahoo.athenz.auth.KeyStore;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class TokenConfigOptionsTest {

    @Test
    public void testDefaultConstructor() {
        TokenConfigOptions options = new TokenConfigOptions();
        assertNotNull(options);
        assertNull(options.getPublicKeyProvider());
        assertNull(options.getOauth2Issuer());
        assertNull(options.getJwtIDTProcessor());
        assertNull(options.getJwtJAGProcessor());
    }

    @Test
    public void testPublicKeyProviderGetterAndSetter() {
        TokenConfigOptions options = new TokenConfigOptions();
        
        // Initially null
        assertNull(options.getPublicKeyProvider());
        
        // Set a mock KeyStore
        KeyStore mockKeyStore = Mockito.mock(KeyStore.class);
        options.setPublicKeyProvider(mockKeyStore);
        assertNotNull(options.getPublicKeyProvider());
        assertEquals(options.getPublicKeyProvider(), mockKeyStore);
        
        // Set to null
        options.setPublicKeyProvider(null);
        assertNull(options.getPublicKeyProvider());
        
        // Set a different KeyStore
        KeyStore anotherKeyStore = Mockito.mock(KeyStore.class);
        options.setPublicKeyProvider(anotherKeyStore);
        assertEquals(options.getPublicKeyProvider(), anotherKeyStore);
    }

    @Test
    public void testOauth2IssuerGetterAndSetter() {
        TokenConfigOptions options = new TokenConfigOptions();
        
        // Initially null
        assertNull(options.getOauth2Issuer());
        
        // Set a value
        String issuer = "https://athenz.io/zts/v1";
        options.setOauth2Issuer(issuer);
        assertNotNull(options.getOauth2Issuer());
        assertEquals(options.getOauth2Issuer(), issuer);
        
        // Set to null
        options.setOauth2Issuer(null);
        assertNull(options.getOauth2Issuer());
        
        // Set a different value
        String anotherIssuer = "https://example.com/oauth2";
        options.setOauth2Issuer(anotherIssuer);
        assertEquals(options.getOauth2Issuer(), anotherIssuer);
        
        // Set empty string
        options.setOauth2Issuer("");
        assertEquals(options.getOauth2Issuer(), "");
    }

    @Test
    public void testJwtIDTProcessorGetterAndSetter() {
        TokenConfigOptions options = new TokenConfigOptions();
        
        // Initially null
        assertNull(options.getJwtIDTProcessor());
        
        // Set a mock processor
        @SuppressWarnings("unchecked")
        ConfigurableJWTProcessor<SecurityContext> mockProcessor = 
            Mockito.mock(ConfigurableJWTProcessor.class);
        options.setJwtIDTProcessor(mockProcessor);
        assertNotNull(options.getJwtIDTProcessor());
        assertEquals(options.getJwtIDTProcessor(), mockProcessor);
        
        // Set to null
        options.setJwtIDTProcessor(null);
        assertNull(options.getJwtIDTProcessor());
        
        // Set a different processor
        @SuppressWarnings("unchecked")
        ConfigurableJWTProcessor<SecurityContext> anotherProcessor = 
            Mockito.mock(ConfigurableJWTProcessor.class);
        options.setJwtIDTProcessor(anotherProcessor);
        assertEquals(options.getJwtIDTProcessor(), anotherProcessor);
    }

    @Test
    public void testJwtJAGProcessorGetterAndSetter() {
        TokenConfigOptions options = new TokenConfigOptions();
        
        // Initially null
        assertNull(options.getJwtJAGProcessor());
        
        // Set a mock processor
        @SuppressWarnings("unchecked")
        ConfigurableJWTProcessor<SecurityContext> mockProcessor = 
            Mockito.mock(ConfigurableJWTProcessor.class);
        options.setJwtJAGProcessor(mockProcessor);
        assertNotNull(options.getJwtJAGProcessor());
        assertEquals(options.getJwtJAGProcessor(), mockProcessor);
        
        // Set to null
        options.setJwtJAGProcessor(null);
        assertNull(options.getJwtJAGProcessor());
        
        // Set a different processor
        @SuppressWarnings("unchecked")
        ConfigurableJWTProcessor<SecurityContext> anotherProcessor = 
            Mockito.mock(ConfigurableJWTProcessor.class);
        options.setJwtJAGProcessor(anotherProcessor);
        assertEquals(options.getJwtJAGProcessor(), anotherProcessor);
    }

    @Test
    public void testAllFieldsSetAndGet() {
        TokenConfigOptions options = new TokenConfigOptions();
        
        KeyStore mockKeyStore = Mockito.mock(KeyStore.class);
        String issuer = "https://athenz.io/zts/v1";
        @SuppressWarnings("unchecked")
        ConfigurableJWTProcessor<SecurityContext> mockIDTProcessor = 
            Mockito.mock(ConfigurableJWTProcessor.class);
        @SuppressWarnings("unchecked")
        ConfigurableJWTProcessor<SecurityContext> mockJAGProcessor = 
            Mockito.mock(ConfigurableJWTProcessor.class);
        
        // Set all fields
        options.setPublicKeyProvider(mockKeyStore);
        options.setOauth2Issuer(issuer);
        options.setJwtIDTProcessor(mockIDTProcessor);
        options.setJwtJAGProcessor(mockJAGProcessor);
        
        // Verify all fields are set correctly
        assertEquals(options.getPublicKeyProvider(), mockKeyStore);
        assertEquals(options.getOauth2Issuer(), issuer);
        assertEquals(options.getJwtIDTProcessor(), mockIDTProcessor);
        assertEquals(options.getJwtJAGProcessor(), mockJAGProcessor);
    }

    @Test
    public void testIndependentFields() {
        TokenConfigOptions options = new TokenConfigOptions();
        
        KeyStore mockKeyStore = Mockito.mock(KeyStore.class);
        @SuppressWarnings("unchecked")
        ConfigurableJWTProcessor<SecurityContext> mockIDTProcessor = 
            Mockito.mock(ConfigurableJWTProcessor.class);
        @SuppressWarnings("unchecked")
        ConfigurableJWTProcessor<SecurityContext> mockJAGProcessor = 
            Mockito.mock(ConfigurableJWTProcessor.class);
        
        // Set IDT processor
        options.setJwtIDTProcessor(mockIDTProcessor);
        assertNotNull(options.getJwtIDTProcessor());
        assertNull(options.getJwtJAGProcessor());
        
        // Set JAG processor independently
        options.setJwtJAGProcessor(mockJAGProcessor);
        assertNotNull(options.getJwtIDTProcessor());
        assertNotNull(options.getJwtJAGProcessor());
        assertNotEquals(options.getJwtIDTProcessor(), options.getJwtJAGProcessor());
        
        // Set public key provider independently
        options.setPublicKeyProvider(mockKeyStore);
        assertNotNull(options.getPublicKeyProvider());
        assertNotNull(options.getJwtIDTProcessor());
        assertNotNull(options.getJwtJAGProcessor());
    }
}

