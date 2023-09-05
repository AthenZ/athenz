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
package com.yahoo.athenz.auth.oauth.validator;

import static org.testng.Assert.*;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Supplier;
import com.yahoo.athenz.auth.oauth.token.OAuthJwtAccessToken;
import com.yahoo.athenz.auth.oauth.token.OAuthJwtAccessTokenException;
import org.mockito.Mockito;
import org.testng.Assert.ThrowingRunnable;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class DefaultOAuthJwtAccessTokenValidatorTest {

    private static final Consumer<ThrowingRunnable> assertDoesNotThrow = (func) -> {
        try {
            func.run();
        } catch (Throwable t) {
            fail("assertDoesNotThrow: unexpected throw", t);
        }
    };
    private static final BiConsumer<ThrowingRunnable, String> assertThrowable = (func, expectedErrMsg) -> {
        try {
            func.run();
        } catch (OAuthJwtAccessTokenException e) {
            assertEquals(e.getMessage(), expectedErrMsg);
            return;
        } catch (Throwable t) {
            fail("assertThrowable: unexpected throw", t);
        }
        fail("assertThrowable: does not throw");
    };

    private final String trustedIssuer = "trustedIssuer";
    private final Set<String> requiredAudiences = new HashSet<>(Arrays.asList("aud_1", "aud_2"));
    private final Set<String> requiredScopes = new HashSet<>(Arrays.asList("scope_1", "scope_2"));
    private final Map<String, Set<String>> authorizedClientIds = Collections.synchronizedMap(new HashMap<>());
    private final DefaultOAuthJwtAccessTokenValidator baseValidator = new DefaultOAuthJwtAccessTokenValidator(this.trustedIssuer, this.requiredAudiences, this.requiredScopes, this.authorizedClientIds);
    private final OAuthJwtAccessToken baseJwt = new OAuthJwtAccessToken() {
        public String getScope() { return null; }
        public String getSubject() { return null; }
        public String getIssuer() { return null; }
        public String getAudience() { return null; }
        public List<String>  getAudiences() { return null; }
        public String getClientId() { return null; }
        public String getCertificateThumbprint() { return null; }
        public long getIssuedAt() { return 0L; }
        public long getExpiration() { return 0L; }
        public String getSignature() { return null; }
    };

    @BeforeMethod
    public void initialize() {
        this.authorizedClientIds.put("client_cert_common_name", new HashSet<>(Arrays.asList("client_id_1", "CLIENT_ID_2")));
    }

    @Test
    public void testDefaultOAuthJwtAccessTokenValidator() {
        // on null or empty
        BiConsumer<Supplier<DefaultOAuthJwtAccessTokenValidator>, String> assertThrowable = (func, expectedErrMsg) -> {
            DefaultOAuthJwtAccessTokenValidator validator = null;
            try {
                validator = func.get();
            } catch (IllegalArgumentException e) {
                assertEquals(e.getMessage(), expectedErrMsg);
                return;
            } finally {
                assertNull(validator);
            }
            fail("assertThrowable: does not throw");
        };
        assertThrowable.accept(() -> new DefaultOAuthJwtAccessTokenValidator(null, this.requiredAudiences, this.requiredScopes, this.authorizedClientIds), "trusted issuers must be configured");
        assertThrowable.accept(() -> new DefaultOAuthJwtAccessTokenValidator("", this.requiredAudiences, this.requiredScopes, this.authorizedClientIds), "trusted issuers must be configured");
        assertThrowable.accept(() -> new DefaultOAuthJwtAccessTokenValidator(this.trustedIssuer, null, this.requiredScopes, this.authorizedClientIds), "required audiences must be configured");
        assertThrowable.accept(() -> new DefaultOAuthJwtAccessTokenValidator(this.trustedIssuer, new HashSet<>(), this.requiredScopes, this.authorizedClientIds), "required audiences must be configured");
        assertThrowable.accept(() -> new DefaultOAuthJwtAccessTokenValidator(this.trustedIssuer, this.requiredAudiences, null, this.authorizedClientIds), "required scopes must be configured");
        assertThrowable.accept(() -> new DefaultOAuthJwtAccessTokenValidator(this.trustedIssuer, this.requiredAudiences, new HashSet<>(), this.authorizedClientIds), "required scopes must be configured");
        assertThrowable.accept(() -> new DefaultOAuthJwtAccessTokenValidator(this.trustedIssuer, this.requiredAudiences, this.requiredScopes, null), "client ID mapping must be configured");

        // actual value
        BiFunction<Field, DefaultOAuthJwtAccessTokenValidator, Object> getFieldValue = (f, object) -> {
            try {
                f.setAccessible(true);
                return f.get(object);
            } catch (IllegalArgumentException | IllegalAccessException e) {
                throw new RuntimeException(e);
            }
        };
        DefaultOAuthJwtAccessTokenValidator validator = new DefaultOAuthJwtAccessTokenValidator(this.trustedIssuer, this.requiredAudiences, this.requiredScopes, this.authorizedClientIds);
        assertNotNull(validator);
        for (Field f : validator.getClass().getDeclaredFields()) {
            switch (f.getName()) {
                case "trustedIssuer":
                    assertSame(getFieldValue.apply(f, validator), this.trustedIssuer);
                    break;
                case "requiredAudiences":
                    assertSame(getFieldValue.apply(f, validator), this.requiredAudiences);
                    break;
                case "requiredScopes":
                    assertSame(getFieldValue.apply(f, validator), this.requiredScopes);
                    break;
                case "authorizedClientIds":
                    assertSame(getFieldValue.apply(f, validator), this.authorizedClientIds);
                    break;
            }
        }
    }

    @Test
    public void testValidateVerifyIssuer() {
        final DefaultOAuthJwtAccessTokenValidator validator = this.baseValidator;
        final OAuthJwtAccessToken mock = Mockito.spy(baseJwt);
        Mockito.doReturn(new ArrayList<>(this.requiredAudiences)).when(mock).getAudiences();
        Mockito.doReturn(new ArrayList<>(this.requiredScopes)).when(mock).getScopes();
        Mockito.doReturn(1L).when(mock).getExpiration();

        // null JWT issuer
        Mockito.doReturn(null).when(mock).getIssuer();
        assertThrowable.accept(() -> validator.validate(mock), "iss not trusted: got=null");

        // empty
        Mockito.doReturn("").when(mock).getIssuer();
        assertThrowable.accept(() -> validator.validate(mock), "iss not trusted: got=");

        // not match
        Mockito.doReturn("untrusty_issuer").when(mock).getIssuer();
        assertThrowable.accept(() -> validator.validate(mock), "iss not trusted: got=untrusty_issuer");

        // match
        Mockito.doReturn("trustedIssuer").when(mock).getIssuer();
        assertDoesNotThrow.accept(() -> validator.validate(mock));
    }

    @Test
    public void testValidateVerifyAudiences() {
        final DefaultOAuthJwtAccessTokenValidator validator = this.baseValidator;
        final OAuthJwtAccessToken mock = Mockito.spy(baseJwt);
        Mockito.doReturn(this.trustedIssuer).when(mock).getIssuer();
        Mockito.doReturn(new ArrayList<>(this.requiredScopes)).when(mock).getScopes();
        Mockito.doReturn(1L).when(mock).getExpiration();

        // null JWT issuer
        Mockito.doReturn(null).when(mock).getAudiences();
        assertThrowable.accept(() -> validator.validate(mock), "required aud not found: got=null");

        // empty
        Mockito.doReturn(new ArrayList<>()).when(mock).getAudiences();
        assertThrowable.accept(() -> validator.validate(mock), "required aud not found: got=");

        // not match
        Mockito.doReturn(Arrays.asList("aud_1", "unknown_aud")).when(mock).getAudiences();
        assertThrowable.accept(() -> validator.validate(mock), "required aud not found: got=aud_1, unknown_aud");

        // match
        Mockito.doReturn(Arrays.asList("aud_3", "aud_2", "aud_1")).when(mock).getAudiences();
        assertDoesNotThrow.accept(() -> validator.validate(mock));
    }

    @Test
    public void testValidateVerifyScopes() {
        final DefaultOAuthJwtAccessTokenValidator validator = this.baseValidator;
        final OAuthJwtAccessToken mock = Mockito.spy(baseJwt);
        Mockito.doReturn(this.trustedIssuer).when(mock).getIssuer();
        Mockito.doReturn(new ArrayList<>(this.requiredAudiences)).when(mock).getAudiences();
        Mockito.doReturn(1L).when(mock).getExpiration();

        // null JWT issuer
        Mockito.doReturn(null).when(mock).getScope();
        assertThrowable.accept(() -> validator.validate(mock), "required scope not found: got=null");

        // empty
        Mockito.doReturn("").when(mock).getScope();
        assertThrowable.accept(() -> validator.validate(mock), "required scope not found: got=");

        // not match
        Mockito.doReturn("scope_1 unknown_scope").when(mock).getScope();
        assertThrowable.accept(() -> validator.validate(mock), "required scope not found: got=scope_1 unknown_scope");

        // match
        Mockito.doReturn("scope_3 scope_2 scope_1").when(mock).getScope();
        assertDoesNotThrow.accept(() -> validator.validate(mock));
    }

    @Test
    public void testValidateExpiration() {
        final DefaultOAuthJwtAccessTokenValidator validator = new DefaultOAuthJwtAccessTokenValidator(this.trustedIssuer, this.requiredAudiences, this.requiredScopes, this.authorizedClientIds);
        final OAuthJwtAccessToken mock = Mockito.spy(baseJwt);
        Mockito.doReturn("trustedIssuer").when(mock).getIssuer();
        Mockito.doReturn(Arrays.asList("aud_1", "aud_2")).when(mock).getAudiences();
        Mockito.doReturn(Arrays.asList("scope_1", "scope_2")).when(mock).getScopes();

        // zero exp
        Mockito.doReturn(0L).when(mock).getExpiration();
        assertThrowable.accept(() -> validator.validate(mock), "exp is empty");

        // -ve exp
        Mockito.doReturn(-1L).when(mock).getExpiration();
        assertThrowable.accept(() -> validator.validate(mock), "exp is empty");

        // +ve exp
        Mockito.doReturn(1L).when(mock).getExpiration();
        assertDoesNotThrow.accept(() -> validator.validate(mock));
    }

    @Test
    public void testValidateClientId() {
        final DefaultOAuthJwtAccessTokenValidator validator = this.baseValidator;
        final OAuthJwtAccessToken mock = Mockito.spy(baseJwt);
        Mockito.doReturn(null).when(mock).getClientId();

        // null JWT client ID, null CN, invalid
        assertThrowable.accept(() -> validator.validateClientId(mock, null), "NO mapping of authorized client IDs for certificate principal (null)");
        // null JWT client ID ONLY, no mapping
        assertThrowable.accept(() -> validator.validateClientId(mock, "no_mapping_1"), "NO mapping of authorized client IDs for certificate principal (no_mapping_1)");
        // null JWT client ID ONLY, mapped
        assertThrowable.accept(() -> validator.validateClientId(mock, "client_cert_common_name"), "client_id is not authorized for certificate principal (client_cert_common_name): got=null");

        Mockito.doReturn("jwt_client_id").when(mock).getClientId();

        // null expected client ID ONLY, no mapping
        assertThrowable.accept(() -> validator.validateClientId(mock, null), "NO mapping of authorized client IDs for certificate principal (null)");
        // null expected client ID ONLY, mapped
        authorizedClientIds.put(null, new HashSet<>(Arrays.asList("null_1, null_2")));
        assertThrowable.accept(() -> validator.validateClientId(mock, null), "client_id is not authorized for certificate principal (null): got=jwt_client_id");
        authorizedClientIds.remove(null);

        // not match, no mapping
        assertThrowable.accept(() -> validator.validateClientId(mock, "no_mapping_2"), "NO mapping of authorized client IDs for certificate principal (no_mapping_2)");
        // not match, mapped
        assertThrowable.accept(() -> validator.validateClientId(mock, "client_cert_common_name"), "client_id is not authorized for certificate principal (client_cert_common_name): got=jwt_client_id");

        // match, no mapping
        Mockito.doReturn("match.principal.1").when(mock).getClientId();
        assertThrowable.accept(() -> validator.validateClientId(mock, "match.principal.1"), "NO mapping of authorized client IDs for certificate principal (match.principal.1)");
        // match, mapped
        Mockito.doReturn("client_id_1").when(mock).getClientId();
        assertDoesNotThrow.accept(() -> validator.validateClientId(mock, "client_cert_common_name"));

        // no mapping, case-insensitive, match, invalid
        Mockito.doReturn("match.principal.PPP").when(mock).getClientId();
        assertThrowable.accept(() -> validator.validateClientId(mock, "match.principal.ppp"), "NO mapping of authorized client IDs for certificate principal (match.principal.ppp)");
        // mapped, case-sensitive, match
        Mockito.doReturn("CLIENT_ID_2").when(mock).getClientId();
        assertDoesNotThrow.accept(() -> validator.validateClientId(mock, "client_cert_common_name"));
        // mapped, case-sensitive, not match
        Mockito.doReturn("client_id_2").when(mock).getClientId();
        assertThrowable.accept(() -> validator.validateClientId(mock, "client_cert_common_name"), "client_id is not authorized for certificate principal (client_cert_common_name): got=client_id_2");
    }

    @Test
    public void testValidateCertificateBinding() {
        final DefaultOAuthJwtAccessTokenValidator validator = this.baseValidator;
        final OAuthJwtAccessToken mock = Mockito.spy(baseJwt);
        Mockito.doReturn(null).when(mock).getCertificateThumbprint();

        // null JWT thumbprint, null expected certificate thumbprint
        assertDoesNotThrow.accept(() -> validator.validateCertificateBinding(mock, (String) null));

        // null JWT thumbprint ONLY
        assertThrowable.accept(() -> validator.validateCertificateBinding(mock, "certificate_thumbprint"), "client certificate thumbprint (certificate_thumbprint) not match: got=null");

        Mockito.doReturn("certificate_thumbprint").when(mock).getCertificateThumbprint();

        // null expected certificate thumbprint ONLY
        assertThrowable.accept(() -> validator.validateCertificateBinding(mock, (String) null), "client certificate thumbprint (null) not match: got=certificate_thumbprint");

        // not match
        assertThrowable.accept(() -> validator.validateCertificateBinding(mock, "not_match"), "client certificate thumbprint (not_match) not match: got=certificate_thumbprint");

        // match
        assertDoesNotThrow.accept(() -> {
            validator.validateCertificateBinding(mock, "certificate_thumbprint"); // for coverage
        });
    }

}
