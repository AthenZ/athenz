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

import javax.net.ssl.SSLContext;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.testng.Assert.*;

public class OAuthTokenRequestBuilderTest {

    @Test
    public void testNewBuilderSuccess() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS);
        assertNotNull(builder);
    }

    @Test(expectedExceptions = ZTSClientException.class)
    public void testNewBuilderWithNullDomain() {
        OAuthTokenRequestBuilder.newBuilder(null);
    }

    @Test(expectedExceptions = ZTSClientException.class)
    public void testNewBuilderWithEmptyDomain() {
        OAuthTokenRequestBuilder.newBuilder("");
    }

    @Test
    public void testBuilderPatternRoleNames() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS);
        List<String> roles = Arrays.asList("role1", "role2");
        OAuthTokenRequestBuilder result = builder.roleNames(roles);
        assertSame(result, builder);
    }

    @Test
    public void testBuilderPatternIdTokenServiceName() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS);
        OAuthTokenRequestBuilder result = builder.idTokenServiceName("service1");
        assertSame(result, builder);
    }

    @Test
    public void testBuilderPatternProxyForPrincipal() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS);
        OAuthTokenRequestBuilder result = builder.proxyForPrincipal("principal1");
        assertSame(result, builder);
    }

    @Test
    public void testBuilderPatternAuthorizationDetails() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS);
        OAuthTokenRequestBuilder result = builder.authorizationDetails("details");
        assertSame(result, builder);
    }

    @Test
    public void testBuilderPatternProxyPrincipalSpiffeUris() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS);
        OAuthTokenRequestBuilder result = builder.proxyPrincipalSpiffeUris("spiffe://example.com/service");
        assertSame(result, builder);
    }

    @Test
    public void testBuilderPatternClientAssertionType() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS);
        OAuthTokenRequestBuilder result = builder.clientAssertionType("urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
        assertSame(result, builder);
    }

    @Test
    public void testBuilderPatternClientAssertion() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS);
        OAuthTokenRequestBuilder result = builder.clientAssertion("assertion-value");
        assertSame(result, builder);
    }

    @Test
    public void testBuilderPatternExpiryTime() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS);
        OAuthTokenRequestBuilder result = builder.expiryTime(3600);
        assertSame(result, builder);
    }

    @Test
    public void testBuilderPatternOpenIdIssuer() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS);
        OAuthTokenRequestBuilder result = builder.openIdIssuer(true);
        assertSame(result, builder);
    }

    @Test
    public void testBuilderPatternGrantType() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS);
        OAuthTokenRequestBuilder result = builder.domainName("test.domain");
        assertSame(result, builder);
    }

    @Test
    public void testBuilderPatternRequestedTokenType() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS);
        OAuthTokenRequestBuilder result = builder.requestedTokenType("urn:ietf:params:oauth:token-type:access_token");
        assertSame(result, builder);
    }

    @Test
    public void testBuilderPatternAudience() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS);
        OAuthTokenRequestBuilder result = builder.audience("audience-value");
        assertSame(result, builder);
    }

    @Test
    public void testBuilderPatternResource() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS);
        OAuthTokenRequestBuilder result = builder.resource("resource-value");
        assertSame(result, builder);
    }

    @Test
    public void testBuilderPatternSubjectToken() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS);
        OAuthTokenRequestBuilder result = builder.subjectToken("subject-token-value");
        assertSame(result, builder);
    }

    @Test
    public void testBuilderPatternSubjectTokenType() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS);
        OAuthTokenRequestBuilder result = builder.subjectTokenType("urn:ietf:params:oauth:token-type:access_token");
        assertSame(result, builder);
    }

    @Test
    public void testBuilderPatternAssertion() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS);
        OAuthTokenRequestBuilder result = builder.assertion("assertion-value");
        assertSame(result, builder);
    }

    @Test
    public void testBuilderPatternActorToken() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS);
        OAuthTokenRequestBuilder result = builder.actorToken("actor-token-value");
        assertSame(result, builder);
    }

    @Test
    public void testBuilderPatternActorTokenType() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS);
        OAuthTokenRequestBuilder result = builder.actorTokenType("urn:ietf:params:oauth:token-type:access_token");
        assertSame(result, builder);
    }

    @Test
    public void testGetCacheKeyWithPrincipalDomainAndService() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .domainName("test.domain");
        String cacheKey = builder.getCacheKey("principal.domain", "service", null);
        assertNotNull(cacheKey);
        assertEquals(cacheKey, "p=principal.domain.service;d=test.domain");
    }

    @Test
    public void testGetCacheKeyWithPrincipalDomainOnly() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .domainName("test.domain");
        String cacheKey = builder.getCacheKey("principal.domain", null, null);
        assertNotNull(cacheKey);
        assertEquals(cacheKey, "p=principal.domain;d=test.domain");
    }

    @Test
    public void testGetCacheKeyWithNullPrincipalDomain() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .domainName("test.domain");
        String cacheKey = builder.getCacheKey(null, null, null);
        assertNull(cacheKey);
    }

    @Test
    public void testGetCacheKeyWithSSLContext() throws Exception {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .domainName("test.domain");
        SSLContext sslContext = SSLContext.getDefault();
        String cacheKey = builder.getCacheKey(null, null, sslContext);
        assertNotNull(cacheKey);
        assertTrue(cacheKey.startsWith("p="));
        assertTrue(cacheKey.contains(";d=test.domain"));
    }

    @Test
    public void testGetCacheKeyWithRoleNames() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .roleNames(Arrays.asList("role1", "role2"))
                .domainName("test.domain");
        String cacheKey = builder.getCacheKey("principal.domain", "service", null);
        assertNotNull(cacheKey);
        assertTrue(cacheKey.contains(";r=role1,role2"));
        assertTrue(cacheKey.contains("p=principal.domain.service"));
        assertTrue(cacheKey.contains(";d=test.domain"));
    }

    @Test
    public void testGetCacheKeyWithSingleRole() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .roleNames(Collections.singletonList("role1"))
                .domainName("test.domain");
        String cacheKey = builder.getCacheKey("principal.domain", "service", null);
        assertNotNull(cacheKey);
        assertTrue(cacheKey.contains(";r=role1"));
    }

    @Test
    public void testGetCacheKeyWithMultipleRolesSorted() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .roleNames(Arrays.asList("zebra", "alpha", "beta"))
                .domainName("test.domain");
        String cacheKey = builder.getCacheKey("principal.domain", "service", null);
        assertNotNull(cacheKey);
        assertTrue(cacheKey.contains(";r=alpha,beta,zebra"));
    }

    @Test
    public void testGetCacheKeyWithIdTokenServiceName() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .idTokenServiceName("service1")
                .domainName("test.domain");
        String cacheKey = builder.getCacheKey("principal.domain", "service", null);
        assertNotNull(cacheKey);
        assertTrue(cacheKey.contains(";o=service1"));
    }

    @Test
    public void testGetCacheKeyWithProxyForPrincipal() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .proxyForPrincipal("proxy.principal")
                .domainName("test.domain");
        String cacheKey = builder.getCacheKey("principal.domain", "service", null);
        assertNotNull(cacheKey);
        assertTrue(cacheKey.contains(";u=proxy.principal"));
    }

    @Test
    public void testGetCacheKeyWithAuthorizationDetails() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .authorizationDetails("test-details");
        String cacheKey = builder.getCacheKey("principal.domain", "service", null);
        assertNotNull(cacheKey);
        assertTrue(cacheKey.contains(";z="));
        // The authorization details are hashed and base64 encoded
        assertFalse(cacheKey.contains("test-details"));
    }

    @Test
    public void testGetCacheKeyWithProxyPrincipalSpiffeUris() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .proxyPrincipalSpiffeUris("spiffe://example.com/service");
        String cacheKey = builder.getCacheKey("principal.domain", "service", null);
        assertNotNull(cacheKey);
        assertTrue(cacheKey.contains(";s=spiffe://example.com/service"));
    }

    @Test
    public void testGetCacheKeyWithAllFields() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .domainName("test.domain")
                .roleNames(Arrays.asList("role1", "role2"))
                .idTokenServiceName("service1")
                .proxyForPrincipal("proxy.principal")
                .authorizationDetails("test-details")
                .proxyPrincipalSpiffeUris("spiffe://example.com/service");
        String cacheKey = builder.getCacheKey("principal.domain", "service", null);
        assertNotNull(cacheKey);
        assertTrue(cacheKey.contains("p=principal.domain.service"));
        assertTrue(cacheKey.contains(";d=test.domain"));
        assertTrue(cacheKey.contains(";r=role1,role2"));
        assertTrue(cacheKey.contains(";o=service1"));
        assertTrue(cacheKey.contains(";u=proxy.principal"));
        assertTrue(cacheKey.contains(";z="));
        assertTrue(cacheKey.contains(";s=spiffe://example.com/service"));
    }

    @Test
    public void testGetCacheKeyWithEmptyRoleNames() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .roleNames(new ArrayList<>());
        String cacheKey = builder.getCacheKey("principal.domain", "service", null);
        assertNotNull(cacheKey);
        assertFalse(cacheKey.contains(";r="));
    }

    @Test
    public void testGetCacheKeyWithNullRoleNames() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS);
        String cacheKey = builder.getCacheKey("principal.domain", "service", null);
        assertNotNull(cacheKey);
        assertFalse(cacheKey.contains(";r="));
    }

    @Test
    public void testGetRequestBodyDefault() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .domainName("test.domain");
        String body = builder.getRequestBody();
        assertNotNull(body);
        assertTrue(body.contains("grant_type=client_credentials"));
        assertTrue(body.contains("scope="));
        assertTrue(body.contains(URLEncoder.encode("test.domain:domain", StandardCharsets.UTF_8)));
        assertFalse(body.contains("expires_in="));
    }

    @Test
    public void testGetRequestBodyWithExpiryTime() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .expiryTime(3600);
        String body = builder.getRequestBody();
        assertNotNull(body);
        assertTrue(body.contains("expires_in=3600"));
    }

    @Test
    public void testGetRequestBodyWithZeroExpiryTime() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .expiryTime(0);
        String body = builder.getRequestBody();
        assertNotNull(body);
        assertFalse(body.contains("expires_in="));
    }

    @Test
    public void testGetRequestBodyWithSingleRole() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .roleNames(Collections.singletonList("role1"))
                .domainName("test.domain");
        String body = builder.getRequestBody();
        assertNotNull(body);
        String expectedScope = "test.domain:role.role1";
        assertTrue(body.contains("scope=" + URLEncoder.encode(expectedScope, StandardCharsets.UTF_8)));
    }

    @Test
    public void testGetRequestBodyWithMultipleRoles() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .roleNames(Arrays.asList("role1", "role2"))
                .domainName("test.domain");
        String body = builder.getRequestBody();
        assertNotNull(body);
        String expectedScope = "test.domain:role.role1 test.domain:role.role2";
        assertTrue(body.contains("scope=" + URLEncoder.encode(expectedScope, StandardCharsets.UTF_8)));
    }

    @Test
    public void testGetRequestBodyWithIdTokenServiceName() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .idTokenServiceName("service1")
                .domainName("test.domain");
        String body = builder.getRequestBody();
        assertNotNull(body);
        String expectedScope = "test.domain:domain openid test.domain:service.service1";
        assertTrue(body.contains("scope=" + URLEncoder.encode(expectedScope, StandardCharsets.UTF_8)));
    }

    @Test
    public void testGetRequestBodyWithRolesAndIdTokenServiceName() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .roleNames(List.of("role1"))
                .idTokenServiceName("service1")
                .domainName("test.domain");
        String body = builder.getRequestBody();
        assertNotNull(body);
        String expectedScope = "test.domain:role.role1 openid test.domain:service.service1";
        assertTrue(body.contains("scope=" + URLEncoder.encode(expectedScope, StandardCharsets.UTF_8)));
    }

    @Test
    public void testGetRequestBodyWithProxyForPrincipal() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .proxyForPrincipal("proxy.principal");
        String body = builder.getRequestBody();
        assertNotNull(body);
        assertTrue(body.contains("proxy_for_principal=" + URLEncoder.encode("proxy.principal", StandardCharsets.UTF_8)));
    }

    @Test
    public void testGetRequestBodyWithAuthorizationDetails() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .authorizationDetails("test-details");
        String body = builder.getRequestBody();
        assertNotNull(body);
        assertTrue(body.contains("authorization_details=" + URLEncoder.encode("test-details", StandardCharsets.UTF_8)));
    }

    @Test
    public void testGetRequestBodyWithProxyPrincipalSpiffeUris() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .proxyPrincipalSpiffeUris("spiffe://example.com/service");
        String body = builder.getRequestBody();
        assertNotNull(body);
        assertTrue(body.contains("proxy_principal_spiffe_uris=" + URLEncoder.encode("spiffe://example.com/service", StandardCharsets.UTF_8)));
    }

    @Test
    public void testGetRequestBodyWithClientAssertionType() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .clientAssertionType("urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
        String body = builder.getRequestBody();
        assertNotNull(body);
        assertTrue(body.contains("client_assertion_type=" + URLEncoder.encode("urn:ietf:params:oauth:client-assertion-type:jwt-bearer", StandardCharsets.UTF_8)));
    }

    @Test
    public void testGetRequestBodyWithClientAssertion() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .clientAssertion("assertion-value");
        String body = builder.getRequestBody();
        assertNotNull(body);
        assertTrue(body.contains("client_assertion=" + URLEncoder.encode("assertion-value", StandardCharsets.UTF_8)));
    }

    @Test
    public void testGetRequestBodyWithOpenIdIssuer() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .openIdIssuer(true);
        String body = builder.getRequestBody();
        assertNotNull(body);
        assertTrue(body.contains("openid_issuer=true"));
    }

    @Test
    public void testGetRequestBodyWithOpenIdIssuerFalse() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .openIdIssuer(false);
        String body = builder.getRequestBody();
        assertNotNull(body);
        assertFalse(body.contains("openid_issuer="));
    }

    @Test
    public void testGetRequestBodyWithGrantType() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .domainName("test.domain");
        String body = builder.getRequestBody();
        assertNotNull(body);
        assertTrue(body.contains("grant_type=client_credentials"));
    }

    @Test
    public void testGetRequestBodyWithRequestedTokenType() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .requestedTokenType("urn:ietf:params:oauth:token-type:access_token");
        String body = builder.getRequestBody();
        assertNotNull(body);
        assertTrue(body.contains("requested_token_type=" + URLEncoder.encode("urn:ietf:params:oauth:token-type:access_token", StandardCharsets.UTF_8)));
    }

    @Test
    public void testGetRequestBodyWithAudience() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .audience("audience-value");
        String body = builder.getRequestBody();
        assertNotNull(body);
        assertTrue(body.contains("audience=" + URLEncoder.encode("audience-value", StandardCharsets.UTF_8)));
    }

    @Test
    public void testGetRequestBodyWithResource() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .resource("resource-value");
        String body = builder.getRequestBody();
        assertNotNull(body);
        assertTrue(body.contains("resource=" + URLEncoder.encode("resource-value", StandardCharsets.UTF_8)));
    }

    @Test
    public void testGetRequestBodyWithSubjectToken() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .subjectToken("subject-token-value");
        String body = builder.getRequestBody();
        assertNotNull(body);
        assertTrue(body.contains("subject_token=" + URLEncoder.encode("subject-token-value", StandardCharsets.UTF_8)));
    }

    @Test
    public void testGetRequestBodyWithSubjectTokenType() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .subjectTokenType("urn:ietf:params:oauth:token-type:access_token");
        String body = builder.getRequestBody();
        assertNotNull(body);
        assertTrue(body.contains("subject_token_type=" + URLEncoder.encode("urn:ietf:params:oauth:token-type:access_token", StandardCharsets.UTF_8)));
    }

    @Test
    public void testGetRequestBodyWithAssertion() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .assertion("assertion-value");
        String body = builder.getRequestBody();
        assertNotNull(body);
        assertTrue(body.contains("assertion=" + URLEncoder.encode("assertion-value", StandardCharsets.UTF_8)));
    }

    @Test
    public void testGetRequestBodyWithActorToken() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .actorToken("actor-token-value");
        String body = builder.getRequestBody();
        assertNotNull(body);
        assertTrue(body.contains("actor_token=" + URLEncoder.encode("actor-token-value", StandardCharsets.UTF_8)));
    }

    @Test
    public void testGetRequestBodyWithActorTokenType() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .actorTokenType("urn:ietf:params:oauth:token-type:access_token");
        String body = builder.getRequestBody();
        assertNotNull(body);
        assertTrue(body.contains("actor_token_type=" + URLEncoder.encode("urn:ietf:params:oauth:token-type:access_token", StandardCharsets.UTF_8)));
    }

    @Test
    public void testGetRequestBodyWithAllFields() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .roleNames(Arrays.asList("role1", "role2"))
                .idTokenServiceName("service1")
                .proxyForPrincipal("proxy.principal")
                .authorizationDetails("test-details")
                .proxyPrincipalSpiffeUris("spiffe://example.com/service")
                .clientAssertionType("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                .clientAssertion("assertion-value")
                .expiryTime(3600)
                .openIdIssuer(true)
                .requestedTokenType("urn:ietf:params:oauth:token-type:access_token")
                .audience("audience-value")
                .resource("resource-value")
                .subjectToken("subject-token-value")
                .subjectTokenType("urn:ietf:params:oauth:token-type:access_token")
                .assertion("assertion-value")
                .actorToken("actor-token-value")
                .actorTokenType("urn:ietf:params:oauth:token-type:access_token");

        String body = builder.getRequestBody();
        assertNotNull(body);
        assertTrue(body.contains("grant_type=client_credentials"));
        assertTrue(body.contains("expires_in=3600"));
        assertTrue(body.contains("scope="));
        assertTrue(body.contains("proxy_for_principal="));
        assertTrue(body.contains("authorization_details="));
        assertTrue(body.contains("proxy_principal_spiffe_uris="));
        assertTrue(body.contains("client_assertion_type="));
        assertTrue(body.contains("client_assertion="));
        assertTrue(body.contains("openid_issuer=true"));
        assertTrue(body.contains("requested_token_type="));
        assertTrue(body.contains("audience="));
        assertTrue(body.contains("resource="));
        assertTrue(body.contains("subject_token="));
        assertTrue(body.contains("subject_token_type="));
        assertTrue(body.contains("assertion="));
        assertTrue(body.contains("actor_token="));
        assertTrue(body.contains("actor_token_type="));
    }

    @Test
    public void testGetRequestBodyWithURLEncoding() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .proxyForPrincipal("principal with spaces")
                .authorizationDetails("details&with=special");
        String body = builder.getRequestBody();
        assertNotNull(body);
        assertTrue(body.contains("proxy_for_principal=" + URLEncoder.encode("principal with spaces", StandardCharsets.UTF_8)));
        assertTrue(body.contains("authorization_details=" + URLEncoder.encode("details&with=special", StandardCharsets.UTF_8)));
    }

    @Test
    public void testGetRequestBodyWithEmptyRoleNames() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .roleNames(new ArrayList<>())
                .domainName("test.domain");
        String body = builder.getRequestBody();
        assertNotNull(body);
        String expectedScope = "test.domain:domain";
        assertTrue(body.contains("scope=" + URLEncoder.encode(expectedScope, StandardCharsets.UTF_8)));
    }

    @Test
    public void testGetRequestBodyWithNullRoleNames() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .domainName("test.domain");
        String body = builder.getRequestBody();
        assertNotNull(body);
        String expectedScope = "test.domain:domain";
        assertTrue(body.contains("scope=" + URLEncoder.encode(expectedScope, StandardCharsets.UTF_8)));
    }

    @Test
    public void testChainedBuilderMethods() {
        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .roleNames(List.of("role1"))
                .idTokenServiceName("service1")
                .proxyForPrincipal("proxy.principal")
                .expiryTime(3600)
                .openIdIssuer(true);

        String body = builder.getRequestBody();
        assertNotNull(body);
        assertTrue(body.contains("grant_type=client_credentials"));
        assertTrue(body.contains("expires_in=3600"));
        assertTrue(body.contains("openid_issuer=true"));
    }
}

