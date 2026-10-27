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
package com.yahoo.athenz.zts;

import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.ServerPrivateKey;
import com.yahoo.athenz.auth.token.AccessToken;
import com.yahoo.athenz.auth.token.OAuth2Token;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.zms.DomainData;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zts.cache.DataCache;
import com.yahoo.athenz.zts.store.DataStore;
import com.yahoo.athenz.zts.token.AccessTokenRequest;
import com.yahoo.athenz.zts.token.IssuerResolver;
import com.yahoo.athenz.zts.token.TokenConfigOptions;
import jakarta.servlet.http.HttpServletRequest;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.util.Set;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

public class ZTSImplTokenExchangeExpiryTest {

    private static final long ISSUE_TIME = 1_700_000_000L;

    private ZTSImpl createZts() {
        // Exercise expiry calculation without starting the server or loading signing keys.
        ZTSImpl zts = mock(ZTSImpl.class, CALLS_REAL_METHODS);
        zts.roleTokenDefaultTimeout = 2400;
        zts.roleTokenMaxTimeout = 3600;
        zts.metric = mock(Metric.class);
        return zts;
    }

    private DataCache createDataCache(Integer roleExpiryMins, Integer domainExpiryMins) {
        DataCache data = new DataCache();
        data.setDomainData(new DomainData().setTokenExpiryMins(domainExpiryMins));
        data.processRole(new Role().setName("targetdomain:role.writers").setTokenExpiryMins(roleExpiryMins));
        return data;
    }

    private AccessTokenRequest createRequest(String subjectTokenType, long subjectExpiry, int requestedExpiry) {
        OAuth2Token subjectToken = mock(OAuth2Token.class);
        when(subjectToken.getExpiryTime()).thenReturn(subjectExpiry);
        when(subjectToken.getSubject()).thenReturn("user.test");
        when(subjectToken.getAudience()).thenReturn("sourcedomain");
        when(subjectToken.getClaim(AccessToken.CLAIM_SCOPE_STD)).thenReturn("targetdomain:role.writers");

        AccessTokenRequest request = mock(AccessTokenRequest.class);
        when(request.getSubjectTokenType()).thenReturn(subjectTokenType);
        when(request.getSubjectTokenObj()).thenReturn(subjectToken);
        when(request.getExpiryTime()).thenReturn(requestedExpiry);
        when(request.getAudience()).thenReturn("targetdomain");
        when(request.getScope()).thenReturn("targetdomain:role.writers");
        return request;
    }

    @DataProvider(name = "tokenTimeouts")
    public Object[][] tokenTimeouts() {
        return new Object[][] {
                {120L, 0, null, null, 120},
                {120L, -1, null, null, 120},
                {120L, 600, null, null, 120},
                {3600L, 600, null, null, 600},
                {7200L, 0, null, null, 2400},
                {7200L, 7200, null, null, 3600},
                {7200L, 1800, 10, null, 600},
                {7200L, 1800, null, 5, 300},
                {120L, 1800, 10, null, 120},
                {120L, 1800, null, 5, 120},
                {7200L, 1800, 10, 5, 600},
                {1L, 600, null, null, 1},
                {600L, 600, null, null, 600},
                {(long) Integer.MAX_VALUE + 1, 600, null, null, 600},
        };
    }

    @Test(dataProvider = "tokenTimeouts")
    public void testDetermineTokenExchangeTimeout(long subjectLifetime, int requestedExpiry,
            Integer roleExpiryMins, Integer domainExpiryMins, int expectedTimeout) {
        ZTSImpl zts = createZts();
        AccessTokenRequest request = createRequest(ZTSConsts.OAUTH_TOKEN_TYPE_ACCESS,
                ISSUE_TIME + subjectLifetime, requestedExpiry);

        assertEquals(zts.determineTokenExchangeTimeout(createDataCache(roleExpiryMins, domainExpiryMins),
                Set.of("writers"), request, ISSUE_TIME, "client", "postAccessTokenRequest"), expectedTimeout);
    }

    @DataProvider(name = "expiredSubjectTokens")
    public Object[][] expiredSubjectTokens() {
        return new Object[][] {{ISSUE_TIME}, {ISSUE_TIME - 1}, {0L}, {Long.MIN_VALUE}};
    }

    @Test(dataProvider = "expiredSubjectTokens")
    public void testDetermineTokenExchangeTimeoutRejectsExpiredSubject(long subjectExpiry) {
        ZTSImpl zts = createZts();
        AccessTokenRequest request = createRequest(ZTSConsts.OAUTH_TOKEN_TYPE_ACCESS, subjectExpiry, 600);

        ResourceException exception = expectThrows(ResourceException.class,
                () -> zts.determineTokenExchangeTimeout(createDataCache(null, null), Set.of("writers"),
                        request, ISSUE_TIME, "client", "postAccessTokenRequest"));
        assertEquals(exception.getCode(), ResourceException.BAD_REQUEST);
        assertEquals(exception.getData(ResourceError.class).message, "Subject access token has expired");
    }

    @DataProvider(name = "otherSubjectTokenTypes")
    public Object[][] otherSubjectTokenTypes() {
        return new Object[][] {{ZTSConsts.OAUTH_TOKEN_TYPE_ID}, {ZTSConsts.OAUTH_TOKEN_TYPE_JWT}};
    }

    @Test(dataProvider = "otherSubjectTokenTypes")
    public void testDetermineTokenExchangeTimeoutForOtherSubjectTypes(String subjectTokenType) {
        ZTSImpl zts = createZts();
        AccessTokenRequest request = createRequest(subjectTokenType, ISSUE_TIME + 120, 600);

        assertEquals(zts.determineTokenExchangeTimeout(createDataCache(null, null), Set.of("writers"),
                request, ISSUE_TIME, "client", "postAccessTokenRequest"), 600);
        verify(request.getSubjectTokenObj(), never()).getExpiryTime();
    }

    @Test(dataProvider = "otherSubjectTokenTypes")
    public void testDetermineTokenExchangeTimeoutRecognizesAccessTokenHeader(String subjectTokenType) {
        ZTSImpl zts = createZts();
        AccessTokenRequest request = createRequest(subjectTokenType, ISSUE_TIME + 120, 600);
        when(request.getSubjectTokenObj().getTokenType()).thenReturn(JwtsHelper.TYPE_AT_JWT);

        assertEquals(zts.determineTokenExchangeTimeout(createDataCache(null, null), Set.of("writers"),
                request, ISSUE_TIME, "client", "postAccessTokenRequest"), 120);
    }

    @Test(dataProvider = "otherSubjectTokenTypes")
    public void testDetermineTokenExchangeTimeoutRejectsExpiredAccessTokenWithOtherSubjectType(String subjectTokenType) {
        ZTSImpl zts = createZts();
        AccessTokenRequest request = createRequest(subjectTokenType, ISSUE_TIME - 1, 600);
        when(request.getSubjectTokenObj().getTokenType()).thenReturn(JwtsHelper.TYPE_AT_JWT);

        ResourceException exception = expectThrows(ResourceException.class,
                () -> zts.determineTokenExchangeTimeout(createDataCache(null, null), Set.of("writers"),
                        request, ISSUE_TIME, "client", "postAccessTokenRequest"));
        assertEquals(exception.getCode(), ResourceException.BAD_REQUEST);
    }

    private ZTSImpl createTokenZts(Principal principal, ResourceContext context) {
        ZTSImpl zts = createZts();
        zts.dataStore = mock(DataStore.class);
        zts.authorizer = mock(ZTSAuthorizer.class);
        zts.issuerResolver = mock(IssuerResolver.class);

        DataCache targetData = createDataCache(null, null);
        when(zts.dataStore.getDataCache("targetdomain")).thenReturn(targetData);
        when(zts.dataStore.getDataCache("sourcedomain")).thenReturn(new DataCache());
        when(zts.authorizer.access(anyString(), anyString(), eq(principal), isNull())).thenReturn(true);
        doNothing().when(zts).validate(anyString(), anyString(), anyString(), anyString());
        doNothing().when(zts).setRequestDomain(context, "targetdomain");
        doAnswer(invocation -> {
            Set<String> roles = invocation.getArgument(5);
            roles.add("writers");
            return null;
        }).when(zts.dataStore).getAccessibleRoles(eq(targetData), eq("targetdomain"), anyString(),
                any(String[].class), anyBoolean(), anySet(), eq(false));
        doReturn(mock(ServerPrivateKey.class)).when(zts).getSignPrivateKey(null);
        return zts;
    }

    private Principal createPrincipal(AccessTokenRequest request, boolean delegation) {
        Principal principal = mock(Principal.class);
        when(principal.getFullName()).thenReturn("client.api");
        if (delegation) {
            OAuth2Token actorToken = mock(OAuth2Token.class);
            when(actorToken.getSubject()).thenReturn("client.api");
            when(request.getActorTokenObj()).thenReturn(actorToken);
        }
        return principal;
    }

    @DataProvider(name = "exchangeExpiries")
    public Object[][] exchangeExpiries() {
        return new Object[][] {{false, true}, {true, true}, {false, false}, {true, false}};
    }

    @Test(dataProvider = "exchangeExpiries")
    public void testExchangeResponseExpiry(boolean delegation, boolean limitedBySubject) {
        long subjectExpiry = System.currentTimeMillis() / 1000 + (limitedBySubject ? 120 : 3600);
        AccessTokenRequest request = createRequest(ZTSConsts.OAUTH_TOKEN_TYPE_ACCESS, subjectExpiry, 600);
        Principal principal = createPrincipal(request, delegation);
        ResourceContext context = mock(ResourceContext.class);
        ZTSImpl zts = createTokenZts(principal, context);

        try (MockedConstruction<AccessToken> tokens = mockConstruction(AccessToken.class)) {
            AccessTokenResponse response = zts.processAccessTokenExchangeRequest(context, principal,
                    request, "client", "postAccessTokenRequest");

            assertEquals(tokens.constructed().size(), 1);
            AccessToken issuedToken = tokens.constructed().get(0);
            ArgumentCaptor<Long> issueTime = ArgumentCaptor.forClass(Long.class);
            verify(issuedToken).setIssueTime(issueTime.capture());
            long expectedExpiry = limitedBySubject ? subjectExpiry : issueTime.getValue() + 600;
            verify(issuedToken).setExpiryTime(expectedExpiry);
            assertEquals(response.getExpires_in().longValue(), expectedExpiry - issueTime.getValue());
            assertTrue(expectedExpiry <= subjectExpiry);
        }
    }

    @DataProvider(name = "exchangeModes")
    public Object[][] exchangeModes() {
        return new Object[][] {{false}, {true}};
    }

    @Test(dataProvider = "exchangeModes")
    public void testExchangeRejectsExpiredSubjectBeforeSigning(boolean delegation) {
        AccessTokenRequest request = createRequest(ZTSConsts.OAUTH_TOKEN_TYPE_ACCESS,
                System.currentTimeMillis() / 1000 - 1, 600);
        Principal principal = createPrincipal(request, delegation);
        ResourceContext context = mock(ResourceContext.class);
        ZTSImpl zts = createTokenZts(principal, context);

        ResourceException exception = expectThrows(ResourceException.class,
                () -> zts.processAccessTokenExchangeRequest(context, principal, request,
                        "client", "postAccessTokenRequest"));
        assertEquals(exception.getCode(), ResourceException.BAD_REQUEST);
        verify(zts, never()).getSignPrivateKey(any());
    }

    private RsrcCtxWrapper createRequestContext(Principal principal) {
        RsrcCtxWrapper context = mock(RsrcCtxWrapper.class);
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(context.principal()).thenReturn(principal);
        when(context.getApiName()).thenReturn("postAccessTokenRequest");
        when(context.request()).thenReturn(request);
        return context;
    }

    private ZTSImpl createRequestZts(RsrcCtxWrapper context) {
        ZTSImpl zts = createTokenZts(context.principal(), context);
        zts.tokenConfigOptions = new TokenConfigOptions();
        doReturn("client").when(zts).logPrincipalAndGetDomain(context);
        HttpServletRequest request = context.request();
        doNothing().when(zts).validateRequest(request, "client", "postAccessTokenRequest", false, false);
        return zts;
    }

    @Test
    public void testJwtBearerAssertionUsesExistingTimeout() {
        RsrcCtxWrapper context = createRequestContext(null);
        ZTSImpl zts = createRequestZts(context);
        final String issuer = "https://athenz.example/zts/v1";
        zts.tokenConfigOptions.setOauth2Issuers(Set.of(issuer));
        long assertionExpiry = System.currentTimeMillis() / 1000 + 120;

        // Mock only the JWT parsing/signing boundary; no credential material is needed.
        try (MockedStatic<JwtsHelper> jwts = mockStatic(JwtsHelper.class);
                MockedConstruction<AccessToken> tokens = mockConstruction(AccessToken.class, (token, construction) -> {
                    if (!construction.arguments().isEmpty()) {
                        when(token.getAudience()).thenReturn(issuer);
                        when(token.getSubject()).thenReturn("client.api");
                        when(token.getClaim(OAuth2Token.CLAIM_CLIENT_ID)).thenReturn("client.api");
                        when(token.getClientIdDomainName()).thenReturn("client");
                        when(token.getClientIdServiceName()).thenReturn("api");
                        when(token.getExpiryTime()).thenReturn(assertionExpiry);
                    }
                })) {
            jwts.when(() -> JwtsHelper.extractJWTTokenType("assertion")).thenReturn(JwtsHelper.TYPE_JWT);

            AccessTokenResponse response = zts.postAccessTokenRequest(context,
                    "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer"
                            + "&assertion=assertion&scope=targetdomain:role.writers&expires_in=600");

            assertEquals(tokens.constructed().size(), 2);
            AccessToken issuedToken = tokens.constructed().get(1);
            ArgumentCaptor<Long> issueTime = ArgumentCaptor.forClass(Long.class);
            verify(issuedToken).setIssueTime(issueTime.capture());
            verify(issuedToken).setExpiryTime(issueTime.getValue() + 600);
            assertEquals(response.getExpires_in().intValue(), 600);
            assertTrue(issueTime.getValue() + 600 > assertionExpiry);
            verify(zts, never()).determineTokenExchangeTimeout(any(), anySet(), any(), anyLong(), anyString(), anyString());
        }
    }

    @DataProvider(name = "jwtSubjectExpiries")
    public Object[][] jwtSubjectExpiries() {
        return new Object[][] {
                {JwtsHelper.TYPE_JWT, 120, false},
                {JwtsHelper.TYPE_AT_JWT, 120, true},
                {JwtsHelper.TYPE_AT_JWT, -1, true},
        };
    }

    @Test(dataProvider = "jwtSubjectExpiries")
    public void testJwtSubjectTokenExchangeExpiry(String jwtType, int subjectLifetime, boolean limitedBySubject) {
        Principal principal = mock(Principal.class);
        when(principal.getFullName()).thenReturn("client.api");
        RsrcCtxWrapper context = createRequestContext(principal);
        ZTSImpl zts = createRequestZts(context);
        long subjectExpiry = System.currentTimeMillis() / 1000 + subjectLifetime;

        try (MockedConstruction<OAuth2Token> subjects = mockConstruction(OAuth2Token.class, (token, construction) -> {
            when(token.getSubject()).thenReturn("user.test");
            when(token.getAudience()).thenReturn("sourcedomain");
            when(token.getClaim(AccessToken.CLAIM_SCOPE_STD)).thenReturn("targetdomain:role.writers");
            when(token.getTokenType()).thenReturn(jwtType);
            when(token.getExpiryTime()).thenReturn(subjectExpiry);
        }); MockedConstruction<AccessToken> tokens = mockConstruction(AccessToken.class)) {
            final String request = "grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                    + "&requested_token_type=urn:ietf:params:oauth:token-type:access_token"
                    + "&subject_token=subject&subject_token_type=urn:ietf:params:oauth:token-type:jwt"
                    + "&audience=targetdomain&scope=targetdomain:role.writers&expires_in=600";

            if (subjectLifetime <= 0) {
                ResourceException exception = expectThrows(ResourceException.class,
                        () -> zts.postAccessTokenRequest(context, request));
                assertEquals(exception.getCode(), ResourceException.BAD_REQUEST);
                assertTrue(tokens.constructed().isEmpty());
            } else {
                AccessTokenResponse response = zts.postAccessTokenRequest(context, request);
                assertEquals(tokens.constructed().size(), 1);
                AccessToken issuedToken = tokens.constructed().get(0);
                ArgumentCaptor<Long> issueTime = ArgumentCaptor.forClass(Long.class);
                verify(issuedToken).setIssueTime(issueTime.capture());
                long expectedExpiry = limitedBySubject ? subjectExpiry : issueTime.getValue() + 600;
                verify(issuedToken).setExpiryTime(expectedExpiry);
                assertEquals(response.getExpires_in().longValue(), expectedExpiry - issueTime.getValue());
            }
            assertEquals(subjects.constructed().size(), 1);
        }
    }
}
