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

import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class ProviderConfigTest {

    @Test
    public void testDefaultConstructor() {
        ProviderConfig config = new ProviderConfig();
        assertNotNull(config);
        assertNull(config.getIssuerUri());
        assertNull(config.getProxyUrl());
        assertNull(config.getJwksUri());
        assertNull(config.getProviderClassName());
    }

    @Test
    public void testIssuerUriGetterAndSetter() {
        ProviderConfig config = new ProviderConfig();
        
        // Initially null
        assertNull(config.getIssuerUri());
        
        // Set a value
        String issuerUri = "https://athenz.io/oauth2/v1";
        config.setIssuerUri(issuerUri);
        assertNotNull(config.getIssuerUri());
        assertEquals(config.getIssuerUri(), issuerUri);
        
        // Set to null
        config.setIssuerUri(null);
        assertNull(config.getIssuerUri());
        
        // Set a different value
        String anotherIssuerUri = "https://example.com/oauth2";
        config.setIssuerUri(anotherIssuerUri);
        assertEquals(config.getIssuerUri(), anotherIssuerUri);
        
        // Set empty string
        config.setIssuerUri("");
        assertEquals(config.getIssuerUri(), "");
    }

    @Test
    public void testProxyUrlGetterAndSetter() {
        ProviderConfig config = new ProviderConfig();
        
        // Initially null
        assertNull(config.getProxyUrl());
        
        // Set a value
        String proxyUrl = "https://proxy.example.com";
        config.setProxyUrl(proxyUrl);
        assertNotNull(config.getProxyUrl());
        assertEquals(config.getProxyUrl(), proxyUrl);
        
        // Set to null
        config.setProxyUrl(null);
        assertNull(config.getProxyUrl());
        
        // Set a different value
        String anotherProxyUrl = "https://another-proxy.example.com";
        config.setProxyUrl(anotherProxyUrl);
        assertEquals(config.getProxyUrl(), anotherProxyUrl);
        
        // Set empty string
        config.setProxyUrl("");
        assertEquals(config.getProxyUrl(), "");
    }

    @Test
    public void testJwksUriGetterAndSetter() {
        ProviderConfig config = new ProviderConfig();
        
        // Initially null
        assertNull(config.getJwksUri());
        
        // Set a value
        String jwksUri = "https://athenz.io/.well-known/jwks.json";
        config.setJwksUri(jwksUri);
        assertNotNull(config.getJwksUri());
        assertEquals(config.getJwksUri(), jwksUri);
        
        // Set to null
        config.setJwksUri(null);
        assertNull(config.getJwksUri());
        
        // Set a different value
        String anotherJwksUri = "https://example.com/.well-known/jwks.json";
        config.setJwksUri(anotherJwksUri);
        assertEquals(config.getJwksUri(), anotherJwksUri);
        
        // Set empty string
        config.setJwksUri("");
        assertEquals(config.getJwksUri(), "");
    }

    @Test
    public void testProviderClassNameGetterAndSetter() {
        ProviderConfig config = new ProviderConfig();
        
        // Initially null
        assertNull(config.getProviderClassName());
        
        // Set a value
        String providerClassName = "com.yahoo.athenz.auth.SimpleServiceIdentityProvider";
        config.setProviderClassName(providerClassName);
        assertNotNull(config.getProviderClassName());
        assertEquals(config.getProviderClassName(), providerClassName);
        
        // Set to null
        config.setProviderClassName(null);
        assertNull(config.getProviderClassName());
        
        // Set a different value
        String anotherProviderClassName = "com.example.CustomProvider";
        config.setProviderClassName(anotherProviderClassName);
        assertEquals(config.getProviderClassName(), anotherProviderClassName);
        
        // Set empty string
        config.setProviderClassName("");
        assertEquals(config.getProviderClassName(), "");
    }

    @Test
    public void testAllFieldsSetAndGet() {
        ProviderConfig config = new ProviderConfig();
        
        String issuerUri = "https://athenz.io/oauth2/v1";
        String proxyUrl = "https://proxy.example.com";
        String jwksUri = "https://athenz.io/.well-known/jwks.json";
        String providerClassName = "com.yahoo.athenz.auth.SimpleServiceIdentityProvider";

        // Set all fields
        config.setIssuerUri(issuerUri);
        config.setProxyUrl(proxyUrl);
        config.setJwksUri(jwksUri);
        config.setProviderClassName(providerClassName);

        // Verify all fields are set correctly
        assertEquals(config.getIssuerUri(), issuerUri);
        assertEquals(config.getProxyUrl(), proxyUrl);
        assertEquals(config.getJwksUri(), jwksUri);
        assertEquals(config.getProviderClassName(), providerClassName);
    }

    @Test
    public void testIndependentFields() {
        ProviderConfig config = new ProviderConfig();
        
        // Set issuerUri
        config.setIssuerUri("https://athenz.io/oauth2/v1");
        assertNotNull(config.getIssuerUri());
        assertNull(config.getProxyUrl());
        assertNull(config.getJwksUri());
        assertNull(config.getProviderClassName());

        // Set proxyUrl independently
        config.setProxyUrl("https://proxy.example.com");
        assertNotNull(config.getIssuerUri());
        assertNotNull(config.getProxyUrl());
        assertNull(config.getJwksUri());
        assertNull(config.getProviderClassName());

        // Set jwksUri independently
        config.setJwksUri("https://athenz.io/.well-known/jwks.json");
        assertNotNull(config.getIssuerUri());
        assertNotNull(config.getProxyUrl());
        assertNotNull(config.getJwksUri());
        assertNull(config.getProviderClassName());

        // Set providerClassName independently
        config.setProviderClassName("com.yahoo.athenz.auth.SimpleServiceIdentityProvider");
        assertNotNull(config.getIssuerUri());
        assertNotNull(config.getProxyUrl());
        assertNotNull(config.getJwksUri());
        assertNotNull(config.getProviderClassName());
    }

    @Test
    public void testToString() {
        ProviderConfig config = new ProviderConfig();
        
        // Test toString with all null fields
        String toString = config.toString();
        assertNotNull(toString);
        assertTrue(toString.contains("ProviderConfig{"));
        assertTrue(toString.contains("issuerUri='null'"));
        assertTrue(toString.contains("proxyUrl='null'"));
        assertTrue(toString.contains("jwksUri='null'"));
        assertTrue(toString.contains("providerClassName='null'"));

        // Test toString with all fields set
        config.setIssuerUri("https://athenz.io/oauth2/v1");
        config.setProxyUrl("https://proxy.example.com");
        config.setJwksUri("https://athenz.io/.well-known/jwks.json");
        config.setProviderClassName("com.yahoo.athenz.auth.SimpleServiceIdentityProvider");

        toString = config.toString();
        assertNotNull(toString);
        assertTrue(toString.contains("ProviderConfig{"));
        assertTrue(toString.contains("issuerUri='https://athenz.io/oauth2/v1'"));
        assertTrue(toString.contains("proxyUrl='https://proxy.example.com'"));
        assertTrue(toString.contains("jwksUri='https://athenz.io/.well-known/jwks.json'"));
        assertTrue(toString.contains("providerClassName='com.yahoo.athenz.auth.SimpleServiceIdentityProvider'"));
    }

    @Test
    public void testToStringWithEmptyStrings() {
        ProviderConfig config = new ProviderConfig();
        config.setIssuerUri("");
        config.setProxyUrl("");
        config.setJwksUri("");
        config.setProviderClassName("");

        String toString = config.toString();
        assertNotNull(toString);
        assertTrue(toString.contains("issuerUri=''"));
        assertTrue(toString.contains("proxyUrl=''"));
        assertTrue(toString.contains("jwksUri=''"));
        assertTrue(toString.contains("providerClassName=''"));
    }

    @Test
    public void testMultipleSetOperations() {
        ProviderConfig config = new ProviderConfig();
        
        // Set values multiple times
        config.setIssuerUri("https://first.example.com");
        config.setIssuerUri("https://second.example.com");
        assertEquals(config.getIssuerUri(), "https://second.example.com");
        
        config.setProxyUrl("https://proxy1.example.com");
        config.setProxyUrl("https://proxy2.example.com");
        assertEquals(config.getProxyUrl(), "https://proxy2.example.com");
        
        config.setJwksUri("https://jwks1.example.com");
        config.setJwksUri("https://jwks2.example.com");
        assertEquals(config.getJwksUri(), "https://jwks2.example.com");
        
        config.setProviderClassName("com.example.Provider1");
        config.setProviderClassName("com.example.Provider2");
        assertEquals(config.getProviderClassName(), "com.example.Provider2");
    }
}
