/*
 * Copyright 2020 Yahoo Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
package com.yahoo.athenz.auth.oauth.token;

import static org.testng.Assert.*;

import java.io.FileReader;
import java.lang.reflect.Field;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.function.BiFunction;
import org.bouncycastle.util.io.pem.PemReader;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;

public class DefaultOAuthJwtAccessTokenTest {

	private JwtParser parser = null;

	@BeforeMethod
	public void initialize() throws Exception {
		PublicKey pk = null;
		try (PemReader reader = new PemReader(new FileReader(this.getClass().getClassLoader().getResource("jwt_public.key").getFile()))) {
			pk = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(reader.readPemObject().getContent()));
		}
		this.parser = Jwts.parserBuilder().setSigningKey(pk).setAllowedClockSkewSeconds(60).build();
	}



	// key: ./src/test/resources/jwt_private.key
	private static final String jwtString =
			"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJkb21haW4uc2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXRoZW56LmlvIiwiYXVkIjoiaHR0cHM6Ly96bXMuYXRoZW56LmlvIiwiY2xpZW50X2lkIjoidWkuYXRoZW56LmlvIiwiY25mIjp7Ing1dCNTMjU2IjoieDUwOV9jZXJ0aWZpY2F0ZV9oYXNoIn0sInNjb3BlIjoicmVhZCB3cml0ZSIsImlhdCI6MTQ3MDAwMDAwMCwiZXhwIjo5OTkwMDA5OTk5fQ.RTiededpxlFRERP8tZWX5NjvJ1NmTfdyXYK1q6Pa_x_XSv5_1SIPcV0kU5x2F0BtekL1a-zV88glv7Ii0jFP0DVRA6ShFD0DloJwiadhPsoAy49Giusa_F_zOidTB0uZ4evJxpkxWXsjZ6xDJVt8A68j03nBuV0t5Gn_yBQymahEXzAv-CLIFLNGBDIP9ky8pp9iUhONn3jHpXk8J4tJCx-miUCf0q9Zh05KN6UWPTZy1vdCLgI-dHzZrKoK42P5lFY0lZuGIloln7ylzCvImLkZOxW6EvKtMTTIyeZdY5CMJGiCwYottpTzvFfsMobYA1fw4worHXg8200h09x88lTTAve9Gb_e_hcYY4z5_YuyRAKzO3PDJ9LEaZg7SjwRDfe8raI_SMPFvQW91cFqPGM_K1gN1FHASsnGlIpBUzZ-gtDz707l6JxgiOQlKWvwU3TSbWkn1e-FneGcAaGLGlzzosARfY5qxCj9HCMwbwX0Tw01oOhHkxxjOvLFJUJ4kNzjN0bC87CIUBVnhiWBmQglIfNvY8Gjd3tLFvuIDE8_u3VElLpETpYcx8OKdYuOSP_PD6K20WKo-s2MAhLWK_1aXdNJ3ShZoNUHqkxQVtFBJy1IQcCiffhi46oMiGq2XA2VW_3RIDdrTLFElXghHqya7gXvOmyykTX2Kxg0XsU";
	@Test
	public void testDefaultOAuthJwtAccessToken() {
		BiFunction<Field, DefaultOAuthJwtAccessToken, Object> getFieldValue = (f, object) -> {
			JwtBuilder b = Jwts.builder().setSubject("Bob");
			try {
				f.setAccessible(true);
				return f.get(object);
			} catch (IllegalArgumentException | IllegalAccessException e) {
				throw new RuntimeException(e);
			}
		};

		Jws<Claims> jws = this.parser.parseClaimsJws(jwtString);
		DefaultOAuthJwtAccessToken at = new DefaultOAuthJwtAccessToken(jws);
		assertNotNull(at);
		for (Field f : at.getClass().getDeclaredFields()) {
			switch (f.getName()) {
			case "body":
				assertSame(getFieldValue.apply(f, at), jws.getBody());
				break;
			case "signature":
				assertSame(getFieldValue.apply(f, at), jws.getSignature());
				break;
			}
		}
	}
	@Test
	public void testGetters() {
		DefaultOAuthJwtAccessToken at = new DefaultOAuthJwtAccessToken(this.parser.parseClaimsJws(jwtString));
		assertEquals(at.getSubject(), "domain.service");
		assertEquals(at.getIssuer(), "https://athenz.io");
		assertEquals(at.getAudience(), "https://zms.athenz.io");
		assertEquals(at.getAudiences(), Arrays.asList("https://zms.athenz.io"));
		assertEquals(at.getClientId(), "ui.athenz.io");
		assertEquals(at.getCertificateThumbprint(), "x509_certificate_hash");
		assertEquals(at.getScope(), "read write");
		assertEquals(at.getScopes(), Arrays.asList("read", "write"));
		assertEquals(at.getIssuedAt(), 1470000000L);
		assertEquals(at.getSignature(), "RTiededpxlFRERP8tZWX5NjvJ1NmTfdyXYK1q6Pa_x_XSv5_1SIPcV0kU5x2F0BtekL1a-zV88glv7Ii0jFP0DVRA6ShFD0DloJwiadhPsoAy49Giusa_F_zOidTB0uZ4evJxpkxWXsjZ6xDJVt8A68j03nBuV0t5Gn_yBQymahEXzAv-CLIFLNGBDIP9ky8pp9iUhONn3jHpXk8J4tJCx-miUCf0q9Zh05KN6UWPTZy1vdCLgI-dHzZrKoK42P5lFY0lZuGIloln7ylzCvImLkZOxW6EvKtMTTIyeZdY5CMJGiCwYottpTzvFfsMobYA1fw4worHXg8200h09x88lTTAve9Gb_e_hcYY4z5_YuyRAKzO3PDJ9LEaZg7SjwRDfe8raI_SMPFvQW91cFqPGM_K1gN1FHASsnGlIpBUzZ-gtDz707l6JxgiOQlKWvwU3TSbWkn1e-FneGcAaGLGlzzosARfY5qxCj9HCMwbwX0Tw01oOhHkxxjOvLFJUJ4kNzjN0bC87CIUBVnhiWBmQglIfNvY8Gjd3tLFvuIDE8_u3VElLpETpYcx8OKdYuOSP_PD6K20WKo-s2MAhLWK_1aXdNJ3ShZoNUHqkxQVtFBJy1IQcCiffhi46oMiGq2XA2VW_3RIDdrTLFElXghHqya7gXvOmyykTX2Kxg0XsU");

		assertEquals(at.toString(), "{sub=domain.service, iss=https://athenz.io, aud=https://zms.athenz.io, client_id=ui.athenz.io, cnf={x5t#S256=x509_certificate_hash}, scope=read write, iat=1470000000, exp=9990009999}");
	}

	// key: ./src/test/resources/jwt_private.key
	private static final String irregularJwtString = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJkb21haW5fRERELnNlcnZpY2VfU1NTIiwiaXNzIjoiaHR0cHM6Ly9hdGhlbnouaW8iLCJhdWQiOlsiaHR0cHM6Ly96bXMuYXRoZW56LmlvIiwiaHR0cHM6Ly96dHMuYXRoZW56LmlvIl0sImlhdCI6MTQ3MDAwMDAwMCwiZXhwIjo5OTkwMDA5OTk5fQ.v2Q53skxN8RRi0U__Zt5daDZYHZwb90y6SuJbMfmjppD_s9Y4_DjxaFZPKno5YZXSHVSy9w6oVyDgnAMCWfZJTdCQQLFYHW1Hs66SUxHmlRd29c6qbaFqStLWgcWjoE8yH92aY7JekHko-epFhBXDtTdwCZLisaTWKrqGMFo54e-4Swy-KLgbmkN4ETj1juiiZNQx9BBxIho1IFVByZJg2AfbM5AlAnbvM-TB9YrTwxHNa4URJJNwsvP7RGIWqIzAXSljs6FgDBugMTFRg6AbNRvEYEvSMmxgS5IRrlwhgOcNORAQh68_KMgjIX4pBGhD0MDw3AzqSNvhCDVJ34n4t_ASdkLx9Bech9X0ELvt9b_YK2eWQU8a9NvOu1l7nDTlzC1u-AcJnBaGSBc7d5ZwkM_rhV5b5QMQ9IS-9yIoOxM2HMOYFy7Pgn1MJcFUs5JmWtSNuGp4pCSg4NUPnoFcKe4MYhzMVtki_5zWldwOyr4sZq_mR2uoA5ITTtkhr9_JT25cB-TWQFS91xRAAJaZVhdq16scgKK5ZOP7VDNvN6RjmFloS2a3B-8ZPJU8zvfjF349GhagbGLBxLGSQ7K5ClKY1BI2mtntjBAMaL3Oy-_CxRpOyTtD12WWxUFmAg_V39jvnlD7edADMvuh9a1h1oMd4MaeJLwkR28__WiFAc";
	@Test
	public void testGettersOnIrregularJwt() {
		DefaultOAuthJwtAccessToken at = new DefaultOAuthJwtAccessToken(this.parser.parseClaimsJws(irregularJwtString));
		assertEquals(at.getSubject(), "domain_ddd.service_sss"); // normalized
		assertEquals(at.getIssuer(), "https://athenz.io");
		assertEquals(at.getAudience(), "[https://zms.athenz.io, https://zts.athenz.io]");
		assertEquals(at.getAudiences(), Arrays.asList("https://zms.athenz.io", "https://zts.athenz.io"));
		assertEquals(at.getClientId(), null);
		assertEquals(at.getCertificateThumbprint(), null);
		assertEquals(at.getScope(), null);
		assertEquals(at.getScopes(), null);
		assertEquals(at.getIssuedAt(), 1470000000L);

		assertEquals(at.toString(), "{sub=domain_DDD.service_SSS, iss=https://athenz.io, aud=[https://zms.athenz.io, https://zts.athenz.io], iat=1470000000, exp=9990009999}");
	}

	// key: ./src/test/resources/jwt_private.key
	private static final String emptyJwtString = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.e30.IqroarCD_DWdjEBI86hzXSco7yf9EN8DuGAQ5CYORpntg7I2xtGHALvsfzxO14zc6J70JMdyZJFeJVLk5jBwMDG6U43uP3206WGdEmFEWEnnHE2GyvgY8Sfj6hErYhNCXtjzMdAjM-KB8vh74SLjbADoQw1MTHSQbgjV4cCUhsKvP1Ts8igT0WKl5LZN2RfuDJmtWs04cRAosYnyKbMq6d2CksUN6VwEG_Yb-f_Ezx7v5do1aWb3Yt2SlGG6Qd9-M4Vq4cvHOCHYnVaaLQHhcJdVq1GJAkziEMllf4EGNWSR9r2jSontF56252JJI3LMMWMQYZ7aFBGBzQXq6C_X9vnCMvYMmP3mJVlRU4q1Iy9RSUa7KdLESEWdvqoM4KzqQ7_6uMsL4s378kBB24c8cIDzFu1x0EuYe8VHO55iKUDCgj4vyLmPhb2_4pu83UzAJ7D87PzYllJt62p2QnXZOiW5xvSRNDKAy3wo8f2fx6jhr3sDLoZmdZt3woxuuYvkruo9YHv-8l4zP4Yk6wUL2aGQ-K6QRrc2jw_Of1FNBrkk08lt6YmV6jivHAPIc-Tb6zmfEbzVVjdfMbb8lqbpdfE8xXOx2wgGpNhck7JPFXbFGfLeT2Qv7A19KDfajEjyaJfqqQ1Patf9JjaDiPc0pxx3oNhghK_iD4guFQaD6sQ";
	@Test
	public void testGettersOnEmptyJwt() {
		DefaultOAuthJwtAccessToken at = new DefaultOAuthJwtAccessToken(this.parser.parseClaimsJws(emptyJwtString));
		assertEquals(at.getSubject(), null);
		assertEquals(at.getIssuer(), null);
		assertEquals(at.getAudience(), null);
		assertEquals(at.getAudiences(), null);
		assertEquals(at.getClientId(), null);
		assertEquals(at.getCertificateThumbprint(), null);
		assertEquals(at.getScope(), null);
		assertEquals(at.getScopes(), null);
		assertEquals(at.getIssuedAt(), 0L);

		assertEquals(at.toString(), "{}");
	}

}
