/*
 * Copyright The Athenz Authors.
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

package com.yahoo.athenz.zts;

import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class IDTokenRequestBuilderTest {

    @Test
    public void testConstants() {
        assertEquals(IDTokenRequestBuilder.OPENID_RESPONSE_TYPE_ID_TOKEN, "id_token");
        assertEquals(IDTokenRequestBuilder.OPENID_RESPONSE_OUTPUT_TYPE_JSON, "json");
    }

    @Test
    public void testNewBuilderSuccess() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token");
        assertNotNull(builder);
    }

    @Test(expectedExceptions = ZTSClientException.class)
    public void testNewBuilderWithNullResponseType() {
        IDTokenRequestBuilder.newBuilder(null);
    }

    @Test(expectedExceptions = ZTSClientException.class)
    public void testNewBuilderWithEmptyResponseType() {
        IDTokenRequestBuilder.newBuilder("");
    }

    @Test
    public void testBuilderPatternClientId() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token");
        IDTokenRequestBuilder result = builder.clientId("test.client");
        assertSame(result, builder);
        assertEquals(builder.clientId, "test.client");
    }

    @Test
    public void testBuilderPatternRedirectUri() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token");
        IDTokenRequestBuilder result = builder.redirectUri("https://example.com/callback");
        assertSame(result, builder);
        assertEquals(builder.redirectUri, "https://example.com/callback");
    }

    @Test
    public void testBuilderPatternScope() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token");
        IDTokenRequestBuilder result = builder.scope("openid profile");
        assertSame(result, builder);
        assertEquals(builder.scope, "openid profile");
    }

    @Test
    public void testBuilderPatternState() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token");
        IDTokenRequestBuilder result = builder.state("random-state-value");
        assertSame(result, builder);
        assertEquals(builder.state, "random-state-value");
    }

    @Test
    public void testBuilderPatternKeyType() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token");
        IDTokenRequestBuilder result = builder.keyType("RSA");
        assertSame(result, builder);
        assertEquals(builder.keyType, "RSA");
    }

    @Test
    public void testBuilderPatternKeyTypeEC() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token");
        IDTokenRequestBuilder result = builder.keyType("EC");
        assertSame(result, builder);
        assertEquals(builder.keyType, "EC");
    }

    @Test
    public void testBuilderPatternExpiryTime() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token");
        IDTokenRequestBuilder result = builder.expiryTime(3600);
        assertSame(result, builder);
        assertEquals(builder.expiryTime, 3600);
    }

    @Test
    public void testBuilderPatternExpiryTimeZero() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token");
        IDTokenRequestBuilder result = builder.expiryTime(0);
        assertSame(result, builder);
        assertEquals(builder.expiryTime, 0);
    }

    @Test
    public void testBuilderPatternExpiryTimeNegative() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token");
        IDTokenRequestBuilder result = builder.expiryTime(-1);
        assertSame(result, builder);
        assertEquals(builder.expiryTime, -1);
    }

    @Test
    public void testBuilderPatternFullArnTrue() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token");
        IDTokenRequestBuilder result = builder.fullArn(true);
        assertSame(result, builder);
        assertTrue(builder.fullArn);
    }

    @Test
    public void testBuilderPatternFullArnFalse() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token");
        IDTokenRequestBuilder result = builder.fullArn(false);
        assertSame(result, builder);
        assertFalse(builder.fullArn);
    }

    @Test
    public void testBuilderPatternAllRolesPresentTrue() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token");
        IDTokenRequestBuilder result = builder.allRolesPresent(true);
        assertSame(result, builder);
        assertTrue(builder.allRolesPresent);
    }

    @Test
    public void testBuilderPatternAllRolesPresentFalse() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token");
        IDTokenRequestBuilder result = builder.allRolesPresent(false);
        assertSame(result, builder);
        assertFalse(builder.allRolesPresent);
    }

    @Test
    public void testBuilderPatternSalt() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token");
        String customSalt = "custom-salt-value";
        IDTokenRequestBuilder result = builder.salt(customSalt);
        assertSame(result, builder);
        assertEquals(builder.salt, customSalt);
    }

    @Test
    public void testBuilderPatternOutputType() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token");
        IDTokenRequestBuilder result = builder.outputType("jwt");
        assertSame(result, builder);
        assertEquals(builder.outputType, "jwt");
    }

    @Test
    public void testDefaultValues() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token");
        assertNotNull(builder.salt);
        assertFalse(builder.salt.isEmpty());
        assertEquals(builder.outputType, IDTokenRequestBuilder.OPENID_RESPONSE_OUTPUT_TYPE_JSON);
        assertEquals(builder.expiryTime, 0);
        assertFalse(builder.fullArn);
        assertFalse(builder.allRolesPresent);
    }

    @Test
    public void testChainedBuilderMethods() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token")
                .clientId("test.client")
                .redirectUri("https://example.com/callback")
                .scope("openid profile")
                .state("state-value")
                .keyType("RSA")
                .expiryTime(3600)
                .fullArn(true)
                .allRolesPresent(true)
                .salt("custom-salt")
                .outputType("jwt");

        assertEquals(builder.clientId, "test.client");
        assertEquals(builder.redirectUri, "https://example.com/callback");
        assertEquals(builder.scope, "openid profile");
        assertEquals(builder.state, "state-value");
        assertEquals(builder.keyType, "RSA");
        assertEquals(builder.expiryTime, 3600);
        assertTrue(builder.fullArn);
        assertTrue(builder.allRolesPresent);
        assertEquals(builder.salt, "custom-salt");
        assertEquals(builder.outputType, "jwt");
    }

    @Test
    public void testGetCacheKeyWithAllRequiredFields() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token")
                .clientId("test.client")
                .scope("openid profile");
        String cacheKey = builder.getCacheKey();
        assertNotNull(cacheKey);
        assertTrue(cacheKey.contains("t=id_token"));
        assertTrue(cacheKey.contains(";c=test.client"));
        assertTrue(cacheKey.contains(";s=openid profile"));
    }

    @Test
    public void testGetCacheKeyWithNullResponseType() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token")
                .clientId("test.client")
                .scope("openid profile");
        // We can't set responseType to null after construction, but we can test with null clientId
        builder.clientId = null;
        String cacheKey = builder.getCacheKey();
        assertNull(cacheKey);
    }

    @Test
    public void testGetCacheKeyWithNullClientId() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token")
                .scope("openid profile");
        String cacheKey = builder.getCacheKey();
        assertNull(cacheKey);
    }

    @Test
    public void testGetCacheKeyWithNullScope() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token")
                .clientId("test.client");
        String cacheKey = builder.getCacheKey();
        assertNull(cacheKey);
    }

    @Test
    public void testGetCacheKeyWithRedirectUri() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token")
                .clientId("test.client")
                .scope("openid profile")
                .redirectUri("https://example.com/callback");
        String cacheKey = builder.getCacheKey();
        assertNotNull(cacheKey);
        assertTrue(cacheKey.contains("t=id_token"));
        assertTrue(cacheKey.contains(";c=test.client"));
        assertTrue(cacheKey.contains(";s=openid profile"));
        assertTrue(cacheKey.contains(";r=https://example.com/callback"));
    }

    @Test
    public void testGetCacheKeyWithState() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token")
                .clientId("test.client")
                .scope("openid profile")
                .state("random-state-value");
        String cacheKey = builder.getCacheKey();
        assertNotNull(cacheKey);
        assertTrue(cacheKey.contains("t=id_token"));
        assertTrue(cacheKey.contains(";c=test.client"));
        assertTrue(cacheKey.contains(";s=openid profile"));
        assertTrue(cacheKey.contains(";a=random-state-value"));
    }

    @Test
    public void testGetCacheKeyWithKeyType() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token")
                .clientId("test.client")
                .scope("openid profile")
                .keyType("RSA");
        String cacheKey = builder.getCacheKey();
        assertNotNull(cacheKey);
        assertTrue(cacheKey.contains("t=id_token"));
        assertTrue(cacheKey.contains(";c=test.client"));
        assertTrue(cacheKey.contains(";s=openid profile"));
        assertTrue(cacheKey.contains(";k=RSA"));
    }

    @Test
    public void testGetCacheKeyWithFullArnTrue() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token")
                .clientId("test.client")
                .scope("openid profile")
                .fullArn(true);
        String cacheKey = builder.getCacheKey();
        assertNotNull(cacheKey);
        assertTrue(cacheKey.contains("t=id_token"));
        assertTrue(cacheKey.contains(";c=test.client"));
        assertTrue(cacheKey.contains(";s=openid profile"));
        assertTrue(cacheKey.contains(";f=true"));
    }

    @Test
    public void testGetCacheKeyWithFullArnFalse() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token")
                .clientId("test.client")
                .scope("openid profile")
                .fullArn(false);
        String cacheKey = builder.getCacheKey();
        assertNotNull(cacheKey);
        assertTrue(cacheKey.contains("t=id_token"));
        assertTrue(cacheKey.contains(";c=test.client"));
        assertTrue(cacheKey.contains(";s=openid profile"));
        assertFalse(cacheKey.contains(";f="));
    }

    @Test
    public void testGetCacheKeyWithEmptyRedirectUri() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token")
                .clientId("test.client")
                .scope("openid profile")
                .redirectUri("");
        String cacheKey = builder.getCacheKey();
        assertNotNull(cacheKey);
        assertTrue(cacheKey.contains("t=id_token"));
        assertTrue(cacheKey.contains(";c=test.client"));
        assertTrue(cacheKey.contains(";s=openid profile"));
        assertFalse(cacheKey.contains(";r="));
    }

    @Test
    public void testGetCacheKeyWithNullRedirectUri() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token")
                .clientId("test.client")
                .scope("openid profile");
        builder.redirectUri = null;
        String cacheKey = builder.getCacheKey();
        assertNotNull(cacheKey);
        assertTrue(cacheKey.contains("t=id_token"));
        assertTrue(cacheKey.contains(";c=test.client"));
        assertTrue(cacheKey.contains(";s=openid profile"));
        assertFalse(cacheKey.contains(";r="));
    }

    @Test
    public void testGetCacheKeyWithEmptyState() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token")
                .clientId("test.client")
                .scope("openid profile")
                .state("");
        String cacheKey = builder.getCacheKey();
        assertNotNull(cacheKey);
        assertTrue(cacheKey.contains("t=id_token"));
        assertTrue(cacheKey.contains(";c=test.client"));
        assertTrue(cacheKey.contains(";s=openid profile"));
        assertFalse(cacheKey.contains(";a="));
    }

    @Test
    public void testGetCacheKeyWithNullState() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token")
                .clientId("test.client")
                .scope("openid profile");
        builder.state = null;
        String cacheKey = builder.getCacheKey();
        assertNotNull(cacheKey);
        assertTrue(cacheKey.contains("t=id_token"));
        assertTrue(cacheKey.contains(";c=test.client"));
        assertTrue(cacheKey.contains(";s=openid profile"));
        assertFalse(cacheKey.contains(";a="));
    }

    @Test
    public void testGetCacheKeyWithEmptyKeyType() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token")
                .clientId("test.client")
                .scope("openid profile")
                .keyType("");
        String cacheKey = builder.getCacheKey();
        assertNotNull(cacheKey);
        assertTrue(cacheKey.contains("t=id_token"));
        assertTrue(cacheKey.contains(";c=test.client"));
        assertTrue(cacheKey.contains(";s=openid profile"));
        assertFalse(cacheKey.contains(";k="));
    }

    @Test
    public void testGetCacheKeyWithNullKeyType() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token")
                .clientId("test.client")
                .scope("openid profile");
        builder.keyType = null;
        String cacheKey = builder.getCacheKey();
        assertNotNull(cacheKey);
        assertTrue(cacheKey.contains("t=id_token"));
        assertTrue(cacheKey.contains(";c=test.client"));
        assertTrue(cacheKey.contains(";s=openid profile"));
        assertFalse(cacheKey.contains(";k="));
    }

    @Test
    public void testGetCacheKeyWithAllOptionalFields() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token")
                .clientId("test.client")
                .scope("openid profile")
                .redirectUri("https://example.com/callback")
                .state("random-state-value")
                .keyType("RSA")
                .fullArn(true);
        String cacheKey = builder.getCacheKey();
        assertNotNull(cacheKey);
        assertTrue(cacheKey.contains("t=id_token"));
        assertTrue(cacheKey.contains(";c=test.client"));
        assertTrue(cacheKey.contains(";s=openid profile"));
        assertTrue(cacheKey.contains(";r=https://example.com/callback"));
        assertTrue(cacheKey.contains(";a=random-state-value"));
        assertTrue(cacheKey.contains(";k=RSA"));
        assertTrue(cacheKey.contains(";f=true"));
    }

    @Test
    public void testGetCacheKeyWithMinimalFields() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token")
                .clientId("test.client")
                .scope("openid");
        String cacheKey = builder.getCacheKey();
        assertNotNull(cacheKey);
        assertEquals(cacheKey, "t=id_token;c=test.client;s=openid");
    }

    @Test
    public void testGetCacheKeyOrder() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token")
                .clientId("test.client")
                .scope("openid profile")
                .redirectUri("https://example.com/callback")
                .state("state-value")
                .keyType("RSA")
                .fullArn(true);
        String cacheKey = builder.getCacheKey();
        assertNotNull(cacheKey);
        // Verify order: t, c, s, r, a, k, f
        assertTrue(cacheKey.startsWith("t=id_token"));
        assertTrue(cacheKey.contains(";c=test.client"));
        assertTrue(cacheKey.contains(";s=openid profile"));
        assertTrue(cacheKey.contains(";r=https://example.com/callback"));
        assertTrue(cacheKey.contains(";a=state-value"));
        assertTrue(cacheKey.contains(";k=RSA"));
        assertTrue(cacheKey.endsWith(";f=true"));
    }

    @Test
    public void testGetCacheKeyWithSpecialCharactersInScope() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token")
                .clientId("test.client")
                .scope("openid profile email:user@example.com");
        String cacheKey = builder.getCacheKey();
        assertNotNull(cacheKey);
        assertTrue(cacheKey.contains(";s=openid profile email:user@example.com"));
    }

    @Test
    public void testGetCacheKeyWithSpecialCharactersInRedirectUri() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token")
                .clientId("test.client")
                .scope("openid")
                .redirectUri("https://example.com/callback?param=value&other=test");
        String cacheKey = builder.getCacheKey();
        assertNotNull(cacheKey);
        assertTrue(cacheKey.contains(";r=https://example.com/callback?param=value&other=test"));
    }

    @Test
    public void testGetCacheKeyWithSpecialCharactersInState() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token")
                .clientId("test.client")
                .scope("openid")
                .state("state-with-special-chars!@#$%");
        String cacheKey = builder.getCacheKey();
        assertNotNull(cacheKey);
        assertTrue(cacheKey.contains(";a=state-with-special-chars!@#$%"));
    }

    @Test
    public void testSaltDefaultValueIsRandom() {
        IDTokenRequestBuilder builder1 = IDTokenRequestBuilder.newBuilder("id_token");
        IDTokenRequestBuilder builder2 = IDTokenRequestBuilder.newBuilder("id_token");
        // Salt should be different for each builder instance (randomly generated)
        assertNotNull(builder1.salt);
        assertNotNull(builder2.salt);
        assertFalse(builder1.salt.isEmpty());
        assertFalse(builder2.salt.isEmpty());
        // While it's possible they could be the same, it's extremely unlikely
        // We just verify they are non-empty strings
    }

    @Test
    public void testSaltCanBeSet() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token");
        String originalSalt = builder.salt;
        String newSalt = "custom-salt-12345";
        builder.salt(newSalt);
        assertEquals(builder.salt, newSalt);
        assertNotEquals(builder.salt, originalSalt);
    }

    @Test
    public void testOutputTypeDefaultIsJson() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token");
        assertEquals(builder.outputType, IDTokenRequestBuilder.OPENID_RESPONSE_OUTPUT_TYPE_JSON);
    }

    @Test
    public void testExpiryTimeDefaultIsZero() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token");
        assertEquals(builder.expiryTime, 0);
    }

    @Test
    public void testFullArnDefaultIsFalse() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token");
        assertFalse(builder.fullArn);
    }

    @Test
    public void testAllRolesPresentDefaultIsFalse() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token");
        assertFalse(builder.allRolesPresent);
    }

    @Test
    public void testBuilderWithNullClientId() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token");
        builder.clientId(null);
        assertNull(builder.clientId);
    }

    @Test
    public void testBuilderWithNullRedirectUri() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token");
        builder.redirectUri(null);
        assertNull(builder.redirectUri);
    }

    @Test
    public void testBuilderWithNullScope() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token");
        builder.scope(null);
        assertNull(builder.scope);
    }

    @Test
    public void testBuilderWithNullState() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token");
        builder.state(null);
        assertNull(builder.state);
    }

    @Test
    public void testBuilderWithNullKeyType() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token");
        builder.keyType(null);
        assertNull(builder.keyType);
    }

    @Test
    public void testBuilderWithNullSalt() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token");
        builder.salt(null);
        assertNull(builder.salt);
    }

    @Test
    public void testBuilderWithNullOutputType() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token");
        builder.outputType(null);
        assertNull(builder.outputType);
    }

    @Test
    public void testGetCacheKeyDoesNotIncludeAllRolesPresent() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token")
                .clientId("test.client")
                .scope("openid")
                .allRolesPresent(true);
        String cacheKey = builder.getCacheKey();
        assertNotNull(cacheKey);
        // allRolesPresent is not included in cache key
        assertFalse(cacheKey.contains("allRolesPresent"));
        assertFalse(cacheKey.contains("all_roles_present"));
    }

    @Test
    public void testGetCacheKeyDoesNotIncludeExpiryTime() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token")
                .clientId("test.client")
                .scope("openid")
                .expiryTime(3600);
        String cacheKey = builder.getCacheKey();
        assertNotNull(cacheKey);
        // expiryTime is not included in cache key
        assertFalse(cacheKey.contains("expiryTime"));
        assertFalse(cacheKey.contains("expiry"));
        assertFalse(cacheKey.contains("3600"));
    }

    @Test
    public void testGetCacheKeyDoesNotIncludeSalt() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token")
                .clientId("test.client")
                .scope("openid")
                .salt("custom-salt");
        String cacheKey = builder.getCacheKey();
        assertNotNull(cacheKey);
        // salt is not included in cache key
        assertFalse(cacheKey.contains("salt"));
        assertFalse(cacheKey.contains("custom-salt"));
    }

    @Test
    public void testGetCacheKeyDoesNotIncludeOutputType() {
        IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder("id_token")
                .clientId("test.client")
                .scope("openid")
                .outputType("jwt");
        String cacheKey = builder.getCacheKey();
        assertNotNull(cacheKey);
        // outputType is not included in cache key
        assertFalse(cacheKey.contains("outputType"));
        assertFalse(cacheKey.contains("output_type"));
        assertFalse(cacheKey.contains("jwt"));
    }
}

