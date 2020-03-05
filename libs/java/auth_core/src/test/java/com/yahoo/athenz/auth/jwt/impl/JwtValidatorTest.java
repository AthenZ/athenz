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
package com.yahoo.athenz.auth.jwt.impl;

import java.io.File;
import java.lang.reflect.Field;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.util.Crypto;

import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SigningKeyResolver;

public class JwtValidatorTest {

	private Authority dummyAuthority;
	private Map<String, String> dummyClientIdMap;
	private Map<String, String> dummyAuthorizedServiceMap;
	private SigningKeyResolver dummySigningKeyResolver;
	private Set<String> dummyTrustedIssuers;
	private Set<String> dummyRequiredAudiences;
	private Set<String> dummyRequiredScopes;

	@BeforeClass
	public void initDummyValues() {
		this.dummyAuthority = new Authority() {
			public void initialize() { }
			public String getDomain() { return null; }
			public String getHeader() { return null; }
			public Principal authenticate(String credential, String remoteAddr, String httpMethod, StringBuilder errMsg) { return null; }
		};
		this.dummyClientIdMap = new HashMap<>();
		this.dummyAuthorizedServiceMap = new HashMap<>();
		this.dummySigningKeyResolver = new SigningKeyResolver() {
			public Key resolveSigningKey(JwsHeader header, Claims claims) {
				return null;
			}
			public Key resolveSigningKey(JwsHeader header, String plaintext) {
				return null;
			}
		};
		this.dummyTrustedIssuers = new HashSet<>(Arrays.asList(new String[] { "dummy-issuer" }));
		this.dummyRequiredAudiences = new HashSet<>(Arrays.asList(new String[] { "dummy-audience" }));
		this.dummyRequiredScopes = new HashSet<>(Arrays.asList(new String[] { "dummy-scope" }));

	}

	@Test(expectedExceptions = { IllegalArgumentException.class }, expectedExceptionsMessageRegExp = "authority must be configured")
	public void testJwtValidatorNullAuthority() {
		new JwtValidator(null, this.dummyClientIdMap, this.dummyAuthorizedServiceMap, this.dummySigningKeyResolver, this.dummyTrustedIssuers, this.dummyRequiredAudiences, this.dummyRequiredScopes);
	}

	@Test(expectedExceptions = { IllegalArgumentException.class }, expectedExceptionsMessageRegExp = "client ID mapping must be configured")
	public void testJwtValidatorNullClientIdMap() {
		new JwtValidator(this.dummyAuthority, null, this.dummyAuthorizedServiceMap, this.dummySigningKeyResolver, this.dummyTrustedIssuers, this.dummyRequiredAudiences, this.dummyRequiredScopes);
	}

	@Test(expectedExceptions = { IllegalArgumentException.class }, expectedExceptionsMessageRegExp = "authorized service mapping must be configured")
	public void testJwtValidatorNullAuthorizedServiceMap() {
		new JwtValidator(this.dummyAuthority, this.dummyClientIdMap, null, this.dummySigningKeyResolver, this.dummyTrustedIssuers, this.dummyRequiredAudiences, this.dummyRequiredScopes);
	}

	@Test(expectedExceptions = { IllegalArgumentException.class }, expectedExceptionsMessageRegExp = "signing key resolver must be configured")
	public void testJwtValidatorNullSigningKeyResolver() {
		new JwtValidator(this.dummyAuthority, this.dummyClientIdMap, this.dummyAuthorizedServiceMap, null, this.dummyTrustedIssuers, this.dummyRequiredAudiences, this.dummyRequiredScopes);
	}

	@Test(expectedExceptions = { IllegalArgumentException.class }, expectedExceptionsMessageRegExp = "trusted issuers must be configured")
	public void testJwtValidatorNullTrustedIssuers() {
		new JwtValidator(this.dummyAuthority, this.dummyClientIdMap, this.dummyAuthorizedServiceMap, this.dummySigningKeyResolver, null, this.dummyRequiredAudiences, this.dummyRequiredScopes);
	}

	@Test(expectedExceptions = { IllegalArgumentException.class }, expectedExceptionsMessageRegExp = "required audiences must be configured")
	public void testJwtValidatorNullRequiredAudiences() {
		new JwtValidator(this.dummyAuthority, this.dummyClientIdMap, this.dummyAuthorizedServiceMap, this.dummySigningKeyResolver, this.dummyTrustedIssuers, null, this.dummyRequiredScopes);
	}

	@Test(expectedExceptions = { IllegalArgumentException.class }, expectedExceptionsMessageRegExp = "required scopes must be configured")
	public void testJwtValidatorNullRequiredScopes() {
		new JwtValidator(this.dummyAuthority, this.dummyClientIdMap, this.dummyAuthorizedServiceMap, this.dummySigningKeyResolver, this.dummyTrustedIssuers, this.dummyRequiredAudiences, null);
	}

	@Test(expectedExceptions = { IllegalArgumentException.class }, expectedExceptionsMessageRegExp = "trusted issuers must be configured")
	public void testJwtValidatorEmptyTrustedIssuers() {
		new JwtValidator(this.dummyAuthority, this.dummyClientIdMap, this.dummyAuthorizedServiceMap, this.dummySigningKeyResolver, new HashSet<>(), this.dummyRequiredAudiences, this.dummyRequiredScopes);
	}

	@Test(expectedExceptions = { IllegalArgumentException.class }, expectedExceptionsMessageRegExp = "required audiences must be configured")
	public void testJwtValidatorEmptyRequiredAudiences() {
		new JwtValidator(this.dummyAuthority, this.dummyClientIdMap, this.dummyAuthorizedServiceMap, this.dummySigningKeyResolver, this.dummyTrustedIssuers, new HashSet<>(), this.dummyRequiredScopes);
	}

	@Test(expectedExceptions = { IllegalArgumentException.class }, expectedExceptionsMessageRegExp = "required scopes must be configured")
	public void testJwtValidatorEmptyRequiredScopes() {
		new JwtValidator(this.dummyAuthority, this.dummyClientIdMap, this.dummyAuthorizedServiceMap, this.dummySigningKeyResolver, this.dummyTrustedIssuers, this.dummyRequiredAudiences, new HashSet<>());
	}

	@Test
	public void testJwtValidator() {
		final JwtValidator jwtValidator = new JwtValidator(this.dummyAuthority, this.dummyClientIdMap, this.dummyAuthorizedServiceMap, this.dummySigningKeyResolver, this.dummyTrustedIssuers, this.dummyRequiredAudiences, this.dummyRequiredScopes);

		Function<String, Object> getFieldValue = (String fieldName) -> { try { 	Field field = jwtValidator.getClass().getDeclaredField(fieldName);
				field.setAccessible(true);
				return field.get(jwtValidator);
			} catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException e) {
				return null;
			}
		};

		Assert.assertSame(getFieldValue.apply("authority"), this.dummyAuthority);
		Assert.assertSame(getFieldValue.apply("clientIdMap"), this.dummyClientIdMap);
		Assert.assertSame(getFieldValue.apply("authorizedServiceMap"), this.dummyAuthorizedServiceMap);
		Assert.assertSame(getFieldValue.apply("signingKeyResolver"), this.dummySigningKeyResolver);
		Assert.assertSame(getFieldValue.apply("trustedIssuers"), this.dummyTrustedIssuers);
		Assert.assertSame(getFieldValue.apply("requiredAudiences"), this.dummyRequiredAudiences);
		Assert.assertSame(getFieldValue.apply("requiredScopes"), this.dummyRequiredScopes);
	}

	@Test
	public void testAuthenticate() {
		final String publicKeyPath = "./src/test/resources/jwt_public.key";
		final String privateKeyPath = "./src/test/resources/jwt_private.key";
		final PublicKey publicKey = Crypto.loadPublicKey(new File(publicKeyPath));
		final PrivateKey privateKey = Crypto.loadPrivateKey(new File(privateKeyPath));
		SigningKeyResolver signingKeyResolver = new SigningKeyResolver() { @Override
			public Key resolveSigningKey(JwsHeader header, Claims claims) {
				return publicKey;
			}
			@Override
			public Key resolveSigningKey(JwsHeader header, String plaintext) {
				return publicKey;
			}
		};
		JwtValidator jwtValidator = new JwtValidator(this.dummyAuthority, this.dummyClientIdMap,
		this.dummyAuthorizedServiceMap, signingKeyResolver, this.dummyTrustedIssuers,
		this.dummyRequiredAudiences, this.dummyRequiredScopes);

		String jwsString = Jwts.builder()
			.setIssuer("example-IdP")
			.setSubject("user-domain.username")
			// .setAudience("zms")
			.setIssuedAt(Date.from(Instant.ofEpochSecond(1568192945)))
			.setNotBefore(Date.from(Instant.ofEpochSecond(1568192945)))
			.setExpiration(Date.from(Instant.ofEpochSecond(1599999999)))
			.claim("iss", "dummy-issuer")
			.claim("aud", "dummy-audience")
			.claim("scope", "dummy-scope")
			.claim("client_id", "app-domain.app-name")
			.signWith(privateKey, SignatureAlgorithm.RS256)
			.compact();
		String clientCertCn = "app-domain.app-name";
		String clientCertThumbprint = null;
		StringBuilder errMsg = new StringBuilder(512);
		SimplePrincipal p = jwtValidator.authenticate(jwsString, clientCertCn, clientCertThumbprint, errMsg);

		System.out.println(errMsg);
		Assert.assertNotNull(p);
		Assert.assertSame(p.getAuthority(), this.dummyAuthority);
		Assert.assertEquals(p.getDomain(), "user-domain");
		Assert.assertEquals(p.getName(), "username");
		Assert.assertEquals(p.getApplicationId(), "app-domain.app-name");
		Assert.assertEquals(p.getAuthorizedService(), "app-domain.app-name");
		// Assert.assertEquals(p.getX509Certificate(), null);
		Assert.assertEquals(p.getIssueTime(), 1568192945L * 1000);
		// Assert.assertEquals(p.getCredentials(), "");
		// Assert.assertEquals(p.getUnsignedCredentials(), "");
	}
}

// https://github.com/keycloak/keycloak/blob/5b51c000af92e1e3f04a4f6a4be0ab3a070c336a/core/src/main/java/org/keycloak/representations/AccessToken.java#L102-L115
class CertConf {
	@JsonProperty("x5t#S256")
	protected String certThumbprint;

	public CertConf(String certThumbprint) {
		this.certThumbprint = certThumbprint;
	}

	public String getCertThumbprint() {
		return certThumbprint;
	}

	public void setCertThumbprint(String certThumbprint) {
		this.certThumbprint = certThumbprint;
	}
}
