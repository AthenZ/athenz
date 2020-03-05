/*
 * Copyright 2020 Yahoo Inc.
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
	private final Map<String, Set<String>> clientIdsMap = Collections.synchronizedMap(new HashMap<>());
	private final DefaultOAuthJwtAccessTokenValidator baseValidator = new DefaultOAuthJwtAccessTokenValidator(this.trustedIssuer, this.requiredAudiences, this.requiredScopes, this.clientIdsMap);
	private final OAuthJwtAccessToken baseJwt = new OAuthJwtAccessToken() {
		public String getScope() { return null; }
		public String getSubject() { return null; }
		public String getIssuer() { return null; }
		public String getAudience() { return null; }
		public List<String>  getAudiences() { return null; }
		public String getClientId() { return null; }
		public String getCertificateThumbprint() { return null; }
		public long getIssuedAt() { return 0L; }
		public String getSignature() { return null; }
	};

	@BeforeMethod
	public void initialize() {
		this.clientIdsMap.put("client_cert_common_name", new HashSet<>(Arrays.asList("client_id_1", "CLIENT_ID_2")));
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
		assertThrowable.accept(() -> {
			return new DefaultOAuthJwtAccessTokenValidator(null, this.requiredAudiences, this.requiredScopes, this.clientIdsMap);
		}, "trusted issuers must be configured");
		assertThrowable.accept(() -> {
			return new DefaultOAuthJwtAccessTokenValidator("", this.requiredAudiences, this.requiredScopes, this.clientIdsMap);
		}, "trusted issuers must be configured");
		assertThrowable.accept(() -> {
			return new DefaultOAuthJwtAccessTokenValidator(this.trustedIssuer, null, this.requiredScopes, this.clientIdsMap);
		}, "required audiences must be configured");
		assertThrowable.accept(() -> {
			return new DefaultOAuthJwtAccessTokenValidator(this.trustedIssuer, new HashSet<>(), this.requiredScopes, this.clientIdsMap);
		}, "required audiences must be configured");
		assertThrowable.accept(() -> {
			return new DefaultOAuthJwtAccessTokenValidator(this.trustedIssuer, this.requiredAudiences, null, this.clientIdsMap);
		}, "required scopes must be configured");
		assertThrowable.accept(() -> {
			return new DefaultOAuthJwtAccessTokenValidator(this.trustedIssuer, this.requiredAudiences, new HashSet<>(), this.clientIdsMap);
		}, "required scopes must be configured");
		assertThrowable.accept(() -> {
			return new DefaultOAuthJwtAccessTokenValidator(this.trustedIssuer, this.requiredAudiences, this.requiredScopes, null);
		}, "client ID mapping must be configured");

		// actual value
		BiFunction<Field, DefaultOAuthJwtAccessTokenValidator, Object> getFieldValue = (f, object) -> {
			try {
				f.setAccessible(true);
				return f.get(object);
			} catch (IllegalArgumentException | IllegalAccessException e) {
				throw new RuntimeException(e);
			}
		};
		DefaultOAuthJwtAccessTokenValidator validator = new DefaultOAuthJwtAccessTokenValidator(this.trustedIssuer, this.requiredAudiences, this.requiredScopes, this.clientIdsMap);
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
				case "clientIdsMap":
					assertSame(getFieldValue.apply(f, validator), this.clientIdsMap);
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

		// null JWT issuer
		Mockito.doReturn(null).when(mock).getIssuer();
		assertThrowable.accept(new ThrowingRunnable(){
			public void run() throws Throwable {
				validator.validate(mock);
			}
		}, "iss not trusted: got=null");

		// empty
		Mockito.doReturn("").when(mock).getIssuer();
		assertThrowable.accept(new ThrowingRunnable(){
			public void run() throws Throwable {
				validator.validate(mock);
			}
		}, "iss not trusted: got=");

		// not match
		Mockito.doReturn("untrusty_issuer").when(mock).getIssuer();
		assertThrowable.accept(new ThrowingRunnable(){
			public void run() throws Throwable {
				validator.validate(mock);
			}
		}, "iss not trusted: got=untrusty_issuer");

		// match
		Mockito.doReturn("trustedIssuer").when(mock).getIssuer();
		assertDoesNotThrow.accept(new ThrowingRunnable(){
			public void run() throws Throwable {
				validator.validate(mock);
			}
		});
	}

	@Test
	public void testValidateVerifyAudiences() {
		final DefaultOAuthJwtAccessTokenValidator validator = this.baseValidator;
		final OAuthJwtAccessToken mock = Mockito.spy(baseJwt);
		Mockito.doReturn(this.trustedIssuer).when(mock).getIssuer();
		Mockito.doReturn(new ArrayList<>(this.requiredScopes)).when(mock).getScopes();

		// null JWT issuer
		Mockito.doReturn(null).when(mock).getAudiences();
		assertThrowable.accept(new ThrowingRunnable(){
			public void run() throws Throwable {
				validator.validate(mock);
			}
		}, "required aud not found: got=null");

		// empty
		Mockito.doReturn(new ArrayList<>()).when(mock).getAudiences();
		assertThrowable.accept(new ThrowingRunnable(){
			public void run() throws Throwable {
				validator.validate(mock);
			}
		}, "required aud not found: got=");

		// not match
		Mockito.doReturn(Arrays.asList("aud_1", "unknown_aud")).when(mock).getAudiences();
		assertThrowable.accept(new ThrowingRunnable(){
			public void run() throws Throwable {
				validator.validate(mock);
			}
		}, "required aud not found: got=aud_1, unknown_aud");

		// match
		Mockito.doReturn(Arrays.asList("aud_3", "aud_2", "aud_1")).when(mock).getAudiences();
		assertDoesNotThrow.accept(new ThrowingRunnable(){
			public void run() throws Throwable {
				validator.validate(mock);
			}
		});
	}

	@Test
	public void testValidateVerifyScopes() {
		final DefaultOAuthJwtAccessTokenValidator validator = this.baseValidator;
		final OAuthJwtAccessToken mock = Mockito.spy(baseJwt);
		Mockito.doReturn(this.trustedIssuer).when(mock).getIssuer();
		Mockito.doReturn(new ArrayList<>(this.requiredAudiences)).when(mock).getAudiences();

		// null JWT issuer
		Mockito.doReturn(null).when(mock).getScope();
		assertThrowable.accept(new ThrowingRunnable(){
			public void run() throws Throwable {
				validator.validate(mock);
			}
		}, "required scope not found: got=null");

		// empty
		Mockito.doReturn("").when(mock).getScope();
		assertThrowable.accept(new ThrowingRunnable(){
			public void run() throws Throwable {
				validator.validate(mock);
			}
		}, "required scope not found: got=");

		// not match
		Mockito.doReturn("scope_1 unknown_scope").when(mock).getScope();
		assertThrowable.accept(new ThrowingRunnable(){
			public void run() throws Throwable {
				validator.validate(mock);
			}
		}, "required scope not found: got=scope_1 unknown_scope");

		// match
		Mockito.doReturn("scope_3 scope_2 scope_1").when(mock).getScope();
		assertDoesNotThrow.accept(new ThrowingRunnable(){
			public void run() throws Throwable {
				validator.validate(mock);
			}
		});
	}

	@Test
	public void testValidateClientId() {
		final DefaultOAuthJwtAccessTokenValidator validator = this.baseValidator;
		final OAuthJwtAccessToken mock = Mockito.spy(baseJwt);
		Mockito.doReturn(null).when(mock).getClientId();

		// null JWT client ID, null expected client ID
		assertDoesNotThrow.accept(new ThrowingRunnable(){
			public void run() throws Throwable {
				validator.validateClientId(mock, null);
			}
		});
		// null JWT client ID ONLY, no mapping
		assertThrowable.accept(new ThrowingRunnable(){
			public void run() throws Throwable {
				validator.validateClientId(mock, "no_mapping_1");
			}
		}, "non-mapped client certificate principal (no_mapping_1) not match with client_id: got=null");
		// null JWT client ID ONLY, mapped
		assertThrowable.accept(new ThrowingRunnable(){
			public void run() throws Throwable {
				validator.validateClientId(mock, "client_cert_common_name");
			}
		}, "mapped client certificate principal (client_cert_common_name) not match with client_id: got=null");

		Mockito.doReturn("jwt_client_id").when(mock).getClientId();

		// null expected client ID ONLY, no mapping
		assertThrowable.accept(new ThrowingRunnable(){
			public void run() throws Throwable {
				validator.validateClientId(mock, null);
			}
		}, "non-mapped client certificate principal (null) not match with client_id: got=jwt_client_id");
		// null expected client ID ONLY, mapped
		clientIdsMap.put(null, new HashSet<>(Arrays.asList("null_1, null_2")));
		assertThrowable.accept(new ThrowingRunnable(){
			public void run() throws Throwable {
				validator.validateClientId(mock, null);
			}
		}, "mapped client certificate principal (null) not match with client_id: got=jwt_client_id");
		clientIdsMap.remove(null);

		// not match, no mapping
		assertThrowable.accept(new ThrowingRunnable(){
			public void run() throws Throwable {
				validator.validateClientId(mock, "no_mapping_2");
			}
		}, "non-mapped client certificate principal (no_mapping_2) not match with client_id: got=jwt_client_id");
		// not match, mapped
		assertThrowable.accept(new ThrowingRunnable(){
			public void run() throws Throwable {
				validator.validateClientId(mock, "client_cert_common_name");
			}
		}, "mapped client certificate principal (client_cert_common_name) not match with client_id: got=jwt_client_id");

		// match, no mapping
		Mockito.doReturn("match.principal.1").when(mock).getClientId();
		assertDoesNotThrow.accept(new ThrowingRunnable(){
			public void run() throws Throwable {
				validator.validateClientId(mock, "match.principal.1");
			}
		});
		// match, mapped
		Mockito.doReturn("client_id_1").when(mock).getClientId();
		assertDoesNotThrow.accept(new ThrowingRunnable(){
			public void run() throws Throwable {
				validator.validateClientId(mock, "client_cert_common_name");
			}
		});

		// no mapping, case-insensitive, match
		Mockito.doReturn("match.principal.PPP").when(mock).getClientId();
		assertDoesNotThrow.accept(new ThrowingRunnable(){
			public void run() throws Throwable {
				validator.validateClientId(mock, "match.principal.ppp");
			}
		});
		// mapped, case-sensitive, match
		Mockito.doReturn("CLIENT_ID_2").when(mock).getClientId();
		assertDoesNotThrow.accept(new ThrowingRunnable(){
			public void run() throws Throwable {
				validator.validateClientId(mock, "client_cert_common_name");
			}
		});
		// mapped, case-sensitive, not match
		Mockito.doReturn("client_id_2").when(mock).getClientId();
		assertThrowable.accept(new ThrowingRunnable(){
			public void run() throws Throwable {
				validator.validateClientId(mock, "client_cert_common_name");
			}
		}, "mapped client certificate principal (client_cert_common_name) not match with client_id: got=client_id_2");
	}

	@Test
	public void testValidateCertificateBinding() {
		final DefaultOAuthJwtAccessTokenValidator validator = this.baseValidator;
		final OAuthJwtAccessToken mock = Mockito.spy(baseJwt);
		Mockito.doReturn(null).when(mock).getCertificateThumbprint();

		// null JWT thumbprint, null expected certificate thumbprint
		assertDoesNotThrow.accept(new ThrowingRunnable(){
			public void run() throws Throwable {
				validator.validateCertificateBinding(mock, (String) null);
			}
		});

		// null JWT thumbprint ONLY
		assertThrowable.accept(new ThrowingRunnable(){
			public void run() throws Throwable {
				validator.validateCertificateBinding(mock, "certificate_thumbprint");
			}
		}, "client certificate thumbprint (certificate_thumbprint) not match: got=null");

		Mockito.doReturn("certificate_thumbprint").when(mock).getCertificateThumbprint();

		// null expected certificate thumbprint ONLY
		assertThrowable.accept(new ThrowingRunnable(){
			public void run() throws Throwable {
				validator.validateCertificateBinding(mock, (String) null);
			}
		}, "client certificate thumbprint (null) not match: got=certificate_thumbprint");

		// not match
		assertThrowable.accept(new ThrowingRunnable(){
			public void run() throws Throwable {
				validator.validateCertificateBinding(mock, "not_match");
			}
		}, "client certificate thumbprint (not_match) not match: got=certificate_thumbprint");

		// match
		assertDoesNotThrow.accept(new ThrowingRunnable(){
			public void run() throws Throwable {
				validator.validateCertificateBinding(mock, new String("certificate_thumbprint")); // for coverage
			}
		});
	}

}
