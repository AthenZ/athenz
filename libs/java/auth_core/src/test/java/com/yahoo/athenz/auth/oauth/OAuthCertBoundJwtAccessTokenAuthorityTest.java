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
package com.yahoo.athenz.auth.oauth;

import static org.testng.Assert.*;

import java.io.FileInputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import com.yahoo.athenz.auth.Authority.CredSource;
import com.yahoo.athenz.auth.impl.CertificateIdentityParser;
import com.yahoo.athenz.auth.oauth.parser.DefaultOAuthJwtAccessTokenParser;
import com.yahoo.athenz.auth.oauth.parser.OAuthJwtAccessTokenParser;
import com.yahoo.athenz.auth.oauth.parser.OAuthJwtAccessTokenParserFactory;
import com.yahoo.athenz.auth.oauth.token.OAuthJwtAccessToken;
import com.yahoo.athenz.auth.oauth.token.OAuthJwtAccessTokenException;
import com.yahoo.athenz.auth.oauth.validator.DefaultOAuthJwtAccessTokenValidator;
import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.Principal;
import org.mockito.Mockito;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

public class OAuthCertBoundJwtAccessTokenAuthorityTest {

    private final ClassLoader classLoader = this.getClass().getClassLoader();
    private X509Certificate[] clientCertChain = null;
    private String jwtPublicKey = null;
    private final KeyStore baseKeyStore = new KeyStore() {
        public String getPublicKey(String domain, String service, String keyId) {
            return jwtPublicKey;
        }
    };

    @BeforeTest
    private void loadFiles() throws Exception {
        try (FileInputStream certIs = new FileInputStream(this.classLoader.getResource("jwt_ui.athenz.io.pem").getFile())) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            this.clientCertChain = new X509Certificate[]{ (X509Certificate) cf.generateCertificate(certIs) };
        }
        this.jwtPublicKey = new String(Files.readAllBytes(Paths.get(this.classLoader.getResource("jwt_public.key").toURI())));
    }

    @Test
    public void testSetKeyStore() throws Exception {
        OAuthCertBoundJwtAccessTokenAuthority authority = new OAuthCertBoundJwtAccessTokenAuthority();
        authority.setKeyStore(authority);

        Field f = authority.getClass().getDeclaredField("keyStore");
        f.setAccessible(true);
        assertSame(f.get(authority), authority);
    }

    @Test
    public void testGetPublicKey() throws Exception {
        KeyStore keyStoreMock = Mockito.spy(baseKeyStore);
        Mockito.when(keyStoreMock.getPublicKey("domain", "service", "keyId")).thenReturn("public_key_in_pem");

        OAuthCertBoundJwtAccessTokenAuthority authority = new OAuthCertBoundJwtAccessTokenAuthority();
        authority.setKeyStore(keyStoreMock);

        assertEquals(authority.getPublicKey("domain", "service", "keyId"), "public_key_in_pem");
    }

    @Test
    public void testGetCredSource() throws Exception {
        OAuthCertBoundJwtAccessTokenAuthority authority = new OAuthCertBoundJwtAccessTokenAuthority();
        assertEquals(authority.getCredSource(), CredSource.REQUEST);
    }

    @Test
    public void testGetAuthenticateChallenge() throws Exception {
        OAuthCertBoundJwtAccessTokenAuthority authority = new OAuthCertBoundJwtAccessTokenAuthority();
        assertEquals(authority.getAuthenticateChallenge(), "Bearer realm=\"athenz.io\"");
    }

    @Test
    public void testGetDomain() throws Exception {
        OAuthCertBoundJwtAccessTokenAuthority authority = new OAuthCertBoundJwtAccessTokenAuthority();
        assertEquals(authority.getDomain(), null);
    }

    @Test
    public void testGetHeader() throws Exception {
        OAuthCertBoundJwtAccessTokenAuthority authority = new OAuthCertBoundJwtAccessTokenAuthority();
        assertEquals(authority.getHeader(), "Authorization");
    }

    @Test
    public void testAuthenticateWithHeader() throws Exception {
        OAuthCertBoundJwtAccessTokenAuthority authority = new OAuthCertBoundJwtAccessTokenAuthority();
        assertEquals(authority.authenticate(null, null, null, null), null);
    }

    @Test
    public void testProcessClientIdsMap() throws Exception {
        OAuthCertBoundJwtAccessTokenAuthority authority = new OAuthCertBoundJwtAccessTokenAuthority();
        Method processClientIdsMap = authority.getClass().getDeclaredMethod("processClientIdsMap", String.class, Map.class, Map.class);
        processClientIdsMap.setAccessible(true);
        Map<String, Set<String>> clientIdsMap = new HashMap<>();
        Map<String, String> authorizedServiceMap = new HashMap<>();

        // empty args
        clientIdsMap.clear();
        authorizedServiceMap.clear();
        processClientIdsMap.invoke(authority, null, clientIdsMap, authorizedServiceMap);
        assertEquals(clientIdsMap.size(), 0);
        assertEquals(authorizedServiceMap.size(), 0);
        clientIdsMap.clear();
        authorizedServiceMap.clear();
        processClientIdsMap.invoke(authority, "", clientIdsMap, authorizedServiceMap);
        assertEquals(clientIdsMap.size(), 0);
        assertEquals(authorizedServiceMap.size(), 0);

        // no such file
        String non_existing_filepath = this.classLoader.getResource("client_map_ids.empty.txt").toURI().resolve("./client_map_ids.non_existing.txt").getPath();
        clientIdsMap.clear();
        authorizedServiceMap.clear();
        processClientIdsMap.invoke(authority, non_existing_filepath, clientIdsMap, authorizedServiceMap);
        assertEquals(clientIdsMap.size(), 0);
        assertEquals(authorizedServiceMap.size(), 0);

        // empty file
        clientIdsMap.clear();
        authorizedServiceMap.clear();
        processClientIdsMap.invoke(authority, this.classLoader.getResource("client_map_ids.empty.txt").getPath(), clientIdsMap, authorizedServiceMap);
        assertEquals(clientIdsMap.size(), 0);
        assertEquals(authorizedServiceMap.size(), 0);

        // client_map_ids.txt
        clientIdsMap.clear();
        authorizedServiceMap.clear();
        Map<String, Set<String>> expectedClientIdsMap = new HashMap<>();
        Map<String, String> expectedAuthorizedServiceMap = new HashMap<>();
        expectedClientIdsMap.put("ui_principal_11", new HashSet<>(Arrays.asList(new String[]{"client_id_11","client_id_12"})));
        expectedAuthorizedServiceMap.put("ui_principal_11", "authorized_service_11");
        expectedClientIdsMap.put("ui_principal_21", new HashSet<>(Arrays.asList(new String[]{"client_id_21"})));
        expectedAuthorizedServiceMap.put("ui_principal_21", "authorized_service_21");
        expectedClientIdsMap.put("ui_principal_31", new HashSet<>(Arrays.asList(new String[]{"client_id_31"})));
        expectedAuthorizedServiceMap.put("ui_principal_31", "authorized_service_31");
        expectedClientIdsMap.put("ui_principal_41", new HashSet<>(Arrays.asList(new String[]{"client_id_41","trailing_comma"})));
        expectedAuthorizedServiceMap.put("ui_principal_41", "authorized_service_41");
        processClientIdsMap.invoke(authority, this.classLoader.getResource("client_map_ids.txt").getPath(), clientIdsMap, authorizedServiceMap);
        assertEquals(clientIdsMap, expectedClientIdsMap);
        assertEquals(authorizedServiceMap, expectedAuthorizedServiceMap);
    }

    static final class OAuthCertBoundJwtAccessTokenAuthorityTestParser implements OAuthJwtAccessTokenParser {
        @Override
        public OAuthJwtAccessToken parse(String jwtString) throws OAuthJwtAccessTokenException {
            return null;
        }
    }
    static final class OAuthCertBoundJwtAccessTokenAuthorityTestParserFactory implements OAuthJwtAccessTokenParserFactory {
        @Override
        public OAuthJwtAccessTokenParser create(KeyStore keyStore) throws IllegalArgumentException {
            return new OAuthCertBoundJwtAccessTokenAuthorityTestParser();
        }
    }
    @Test
    public void testInitialize() throws Exception {
        OAuthCertBoundJwtAccessTokenAuthority authority = new OAuthCertBoundJwtAccessTokenAuthority();

        // authenticateChallenge
        Field authenticateChallengeField = authority.getClass().getDeclaredField("authenticateChallenge");
        authenticateChallengeField.setAccessible(true);

        System.setProperty("athenz.auth.oauth.jwt.authn_challenge_realm", "https://realm.athenz.io");
        authority.initialize();
        System.clearProperty("athenz.auth.oauth.jwt.authn_challenge_realm");
        assertEquals(authenticateChallengeField.get(authority), "Bearer realm=\"https://realm.athenz.io\"");

        System.clearProperty("athenz.auth.oauth.jwt.authn_challenge_realm");
        authority.initialize();
        assertEquals(authenticateChallengeField.get(authority), "Bearer realm=\"https://athenz.io\"");

        // certificateIdentityParser
        CertificateIdentityParser certParser = null;
        Field excludeRoleCertificatesField = null, excludedPrincipalsField = null;
        Field certificateIdentityParserField = authority.getClass().getDeclaredField("certificateIdentityParser");
        certificateIdentityParserField.setAccessible(true);

        System.setProperty("athenz.auth.oauth.jwt.cert.exclude_role_certificates", "true");
        System.setProperty("athenz.auth.oauth.jwt.cert.excluded_principals", "principals_1,principals_2");
        authority.initialize();
        System.clearProperty("athenz.auth.oauth.jwt.cert.exclude_role_certificates");
        System.clearProperty("athenz.auth.oauth.jwt.cert.excluded_principals");
        certParser = (CertificateIdentityParser) certificateIdentityParserField.get(authority);
        excludeRoleCertificatesField  = certParser.getClass().getDeclaredField("excludeRoleCertificates");
        excludedPrincipalsField  = certParser.getClass().getDeclaredField("excludedPrincipalSet");
        excludeRoleCertificatesField.setAccessible(true);
        excludedPrincipalsField.setAccessible(true);
        assertEquals(excludeRoleCertificatesField.get(certParser), true);
        assertEquals(excludedPrincipalsField.get(certParser), new HashSet<>(Arrays.asList(new String[]{ "principals_1", "principals_2" })));

        System.clearProperty("athenz.auth.oauth.jwt.cert.exclude_role_certificates");
        System.clearProperty("athenz.auth.oauth.jwt.cert.excluded_principals");
        authority.initialize();
        certParser = (CertificateIdentityParser) certificateIdentityParserField.get(authority);
        excludeRoleCertificatesField  = certParser.getClass().getDeclaredField("excludeRoleCertificates");
        excludedPrincipalsField  = certParser.getClass().getDeclaredField("excludedPrincipalSet");
        excludeRoleCertificatesField.setAccessible(true);
        excludedPrincipalsField.setAccessible(true);
        assertEquals(excludeRoleCertificatesField.get(certParser), false);
        assertEquals(excludedPrincipalsField.get(certParser), (Set<String>) null);

        // parser
        Field parserField = authority.getClass().getDeclaredField("parser");
        parserField.setAccessible(true);

        System.setProperty("athenz.auth.oauth.jwt.parser_factory_class", "invalid_class");
        assertThrows(IllegalArgumentException.class, () -> authority.initialize());
        System.clearProperty("athenz.auth.oauth.jwt.parser_factory_class");

        System.setProperty("athenz.auth.oauth.jwt.parser_factory_class", OAuthCertBoundJwtAccessTokenAuthorityTestParserFactory.class.getName());
        authority.initialize();
        System.clearProperty("athenz.auth.oauth.jwt.parser_factory_class");
        assertTrue(parserField.get(authority) instanceof OAuthCertBoundJwtAccessTokenAuthorityTestParser);

        System.clearProperty("athenz.auth.oauth.jwt.parser_factory_class");
        authority.initialize();
        assertTrue(parserField.get(authority) instanceof DefaultOAuthJwtAccessTokenParser);

        // shouldVerifyCertThumbprint
        Field shouldVerifyCertThumbprintField = authority.getClass().getDeclaredField("shouldVerifyCertThumbprint");
        shouldVerifyCertThumbprintField.setAccessible(true);

        System.clearProperty("athenz.auth.oauth.jwt.verify_cert_thumbprint");
        authority.initialize();
        assertEquals(shouldVerifyCertThumbprintField.get(authority), true);
        System.setProperty("athenz.auth.oauth.jwt.verify_cert_thumbprint", "false");
        authority.initialize();
        System.clearProperty("athenz.auth.oauth.jwt.verify_cert_thumbprint");
        assertEquals(shouldVerifyCertThumbprintField.get(authority), false);

        // authorizedServiceMap & validator
        DefaultOAuthJwtAccessTokenValidator validator = null;
        Field trustedIssuerField = null, requiredAudiencesField = null, requiredScopesField = null, clientIdsMapField = null;
        Field authorizedServiceMapField = authority.getClass().getDeclaredField("authorizedServiceMap");
        authorizedServiceMapField.setAccessible(true);
        Field validatorField = authority.getClass().getDeclaredField("validator");
        validatorField.setAccessible(true);

        System.setProperty("athenz.auth.oauth.jwt.client_id_map_path", "");
        System.setProperty("athenz.auth.oauth.jwt.claim.iss", "");
        System.setProperty("athenz.auth.oauth.jwt.claim.aud", "");
        System.setProperty("athenz.auth.oauth.jwt.claim.scope", "");
        assertThrows(IllegalArgumentException.class, () -> authority.initialize());
        System.clearProperty("athenz.auth.oauth.jwt.client_id_map_path");
        System.clearProperty("athenz.auth.oauth.jwt.claim.iss");
        System.clearProperty("athenz.auth.oauth.jwt.claim.aud");
        System.clearProperty("athenz.auth.oauth.jwt.claim.scope");

        Map<String, String> expectedAuthorizedServiceMap = new HashMap<>();
        Map<String, Set<String>> expectedClientIdsMap = new HashMap<>();
        expectedAuthorizedServiceMap.put("ui.athenz.io", "sys.auth.ui");
        expectedClientIdsMap.put("ui.athenz.io", new HashSet<>(Arrays.asList(new String[]{"client_id_1","client_id_2","ui.athenz.io"})));
        System.setProperty("athenz.auth.oauth.jwt.client_id_map_path", this.classLoader.getResource("client_map_ids.single.txt").getPath());
        System.setProperty("athenz.auth.oauth.jwt.claim.iss", "iss");
        System.setProperty("athenz.auth.oauth.jwt.claim.aud", "aud_1,aud_2");
        System.setProperty("athenz.auth.oauth.jwt.claim.scope", "scope_1 scope_2");
        authority.initialize();
        System.clearProperty("athenz.auth.oauth.jwt.client_id_map_path");
        System.clearProperty("athenz.auth.oauth.jwt.claim.iss");
        System.clearProperty("athenz.auth.oauth.jwt.claim.aud");
        System.clearProperty("athenz.auth.oauth.jwt.claim.scope");
        assertEquals(authorizedServiceMapField.get(authority), expectedAuthorizedServiceMap);
        validator = (DefaultOAuthJwtAccessTokenValidator) validatorField.get(authority);
        trustedIssuerField = validator.getClass().getDeclaredField("trustedIssuer");
        requiredAudiencesField = validator.getClass().getDeclaredField("requiredAudiences");
        requiredScopesField = validator.getClass().getDeclaredField("requiredScopes");
        clientIdsMapField = validator.getClass().getDeclaredField("clientIdsMap");
        trustedIssuerField.setAccessible(true);
        requiredAudiencesField.setAccessible(true);
        requiredScopesField.setAccessible(true);
        clientIdsMapField.setAccessible(true);
        assertEquals(trustedIssuerField.get(validator), "iss");
        assertEquals(requiredAudiencesField.get(validator), new HashSet<>(Arrays.asList(new String[]{"aud_1", "aud_2"})));
        assertEquals(requiredScopesField.get(validator), new HashSet<>(Arrays.asList(new String[]{"scope_1", "scope_2"})));
        assertEquals(clientIdsMapField.get(validator), expectedClientIdsMap);

        System.clearProperty("athenz.auth.oauth.jwt.client_id_map_path");
        System.clearProperty("athenz.auth.oauth.jwt.claim.iss");
        System.clearProperty("athenz.auth.oauth.jwt.claim.aud");
        System.clearProperty("athenz.auth.oauth.jwt.claim.scope");
        authority.initialize();
        assertEquals(authorizedServiceMapField.get(authority), new HashMap<String, String>());
        validator = (DefaultOAuthJwtAccessTokenValidator) validatorField.get(authority);
        trustedIssuerField = validator.getClass().getDeclaredField("trustedIssuer");
        requiredAudiencesField = validator.getClass().getDeclaredField("requiredAudiences");
        requiredScopesField = validator.getClass().getDeclaredField("requiredScopes");
        clientIdsMapField = validator.getClass().getDeclaredField("clientIdsMap");
        trustedIssuerField.setAccessible(true);
        requiredAudiencesField.setAccessible(true);
        requiredScopesField.setAccessible(true);
        clientIdsMapField.setAccessible(true);
        assertEquals(trustedIssuerField.get(validator), "https://athenz.io");
        assertEquals(requiredAudiencesField.get(validator), new HashSet<>(Arrays.asList(new String[]{"https://zms.athenz.io"})));
        assertEquals(requiredScopesField.get(validator), new HashSet<>(Arrays.asList(new String[]{"sys.auth:role.admin"})));
        assertEquals(clientIdsMapField.get(validator), new HashMap<String, String>());
    }

    @Test
    public void testAuthenticate() {
        String expiredJwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleUlkIn0.eyJzdWIiOiJ1c2VyLmFkbWluIiwiaXNzIjoiaHR0cHM6Ly9hdGhlbnouaW8iLCJhdWQiOiJodHRwczovL3ptcy5hdGhlbnouaW8iLCJzY29wZSI6InN5cy5hdXRoOnJvbGUuYWRtaW4iLCJjbGllbnRfaWQiOiJ1aS5hdGhlbnouaW8iLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MTUxNjIzOTAyMn0.rAT2uWb_YrCE5Ntpq8fCaMSMAYFXel2DEhTwkEgK4d0qmr8tRwmtCVc3RsL3q5c5nrFdm_buA4Jz6iAbM6i-ESd-A6t22Sc9EhyFvB6LHgVCtqE8n95BTfKFtwI2VEeObOam1MWikGhha0b2Zb_HqQ5mkxOE67EMX_c6GJKbwU5v6Ub5ydqArRbkMr1-rqvo3ezZJGZgrqhvMDwoq6eD3o-G4lSVmY5X4ojEbqSUAHHjywmYXc3ZnM7EzGJiUqciBxPN6qH7Ky9zCgIxkGYMP9eAWfvdxl_d12C4-BpzNVGfL1JXLvaSP4VI_7FTOi1wXUThNtsqVWI_fbeQU0txlIRdcDTGBDUvIrUqg02WXJvhieX4acY7RsObjbXvCIyfE6zFsRPOw4_2tI8DR0VIyQOnziQ0hRrJvR-2ZntYlKRqqJTeguiuC4Kuv4MGgwBPqwA0KhLEvu4ANkeVxKzOBJtJwp-MK8G8WpsICGZOxJzt_ZBhekXTp0WOF6dlBdWRdiOBMvM-dBtIAVBs_kAOTgbts7WtiES6sz77NE9iH0aTtwv-Re13caH6oVOUfPjP5zJbmem0Lgvth1eVmQxbGM49MQhr5wg1ybacJKYlL3syG_vXQzoDALdof3XxajkYNURfdE-hCcqHFY4yE9zX-Z_QJKr_LamRAFii5zCFx1k";
        String noExpJwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleUlkIn0.eyJzdWIiOiJ1c2VyLmFkbWluIiwiaXNzIjoiaHR0cHM6Ly9hdGhlbnouaW8iLCJhdWQiOiJodHRwczovL3ptcy5hdGhlbnouaW8iLCJzY29wZSI6InN5cy5hdXRoOnJvbGUuYWRtaW4iLCJjbGllbnRfaWQiOiJ1aS5hdGhlbnouaW8iLCJpYXQiOjE1MTYyMzkwMjJ9.cl5JgNBR8rEQwgibjl9l42LgJZVVFFD77zbmlNIBTMv2Yqi4CxaGOQ_pL9L_74cbIvIk1-jAB7jAaCFaXi44jTzxEGtOfjB67Ro4svutBS3LGp8Zb0p5dilbNnkL9QuqzwihR5dmixyFPrzQU2VkZOJ655TDsrWdEERZMP3qyAonf1RVORHPGWZyL5FFXtCnJ9NSZNtc0foO7sR5pcY0HGOSZY8oqvFUsQVq3Uc7CQK8Y0SnIBMTi1COfGsSZb3pduj8zDkS5aCkC6Q62cXuJxCHhsFynUd-FVoa96AN2QA8F_YIbeEDGkLQgQbBGKY8JazJ_kC-Fn7vPLdigd5H1CpOS6M1puIs1mRbI54Bm-0Xr0A9YC87QcjIOIdcnkrPEwMkbvzcUlzWpvx0xzUH91S3oOb-VmJiTYGSRJ1tuGNAwCN_-jkyIFks4XqK-c1-i-r3Yo6ZvL9la4Idefe0HjUKsN_wpHAMb5OC37y0dtyudCWetl_J-Rmx3XiLGUKGj5HOifz98V5qh_4DrEa9cXsslNwGc_8x_OfU3r8ggEDdL09vMl3qim9kCczGWeBreSgcLzibONWjAmpSvnVdyYq9J6PfHhogL_TU_7RjvkOTPkZKBcgitZVhmRvwbuPdz-DChR7xkUhI_IGyZFSMNRtvTiKHxufdLZgxT5UOjLk";
        String noCnfJwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleUlkIn0.eyJzdWIiOiJ1c2VyLmFkbWluIiwiaXNzIjoiaHR0cHM6Ly9hdGhlbnouaW8iLCJhdWQiOiJodHRwczovL3ptcy5hdGhlbnouaW8iLCJzY29wZSI6InN5cy5hdXRoOnJvbGUuYWRtaW4iLCJjbGllbnRfaWQiOiJ1aS5hdGhlbnouaW8iLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6OTk5MDAwOTk5OX0.uUu9l6YbZ7fLgJhmjMprHPp0rk10aXfRgFrJnL5k_WHAqaQW0xyQROM0DU3o96JgIIYcVHiMNNESgpdwxNaI2JVU9aUVGAlda-3nQgtXz-J6a_y5mD4MYJjtK7jipa-GVowwUakC7esGi30j4hhwVIxYIrruwOW3LrEj69E3TWUU1on33XaT-b-l9FgfhuEFn5aArNzOd9oLBqXooqFDDzJ9iFNhi4n8w-6acNPrcmTbF1MSDmzhYJJhvJ_D6fwgmMBFNuXDo0Zj_m3t_-QfYx_s76T6SuZkcs5ie5G4QQPff7zFWLxuEYMYLpaEUq_U2TaiyCYjPBqrBZE6bEhrBeOOYOtslNHK5mhV4BhtQ0KqhrYIeYQfcXLOzsDWe8zvtVzAKR_VfskzNxEKV7fwShMARrKQDdNzCoAq_6jnVL1B74pvhuwwUVCCNu2lT0Jx7o8FM8VHjdEZFQaLhbpokTmUzfDyT8i0zM9YG54umZjNCLo8NmFU4cBBAyjZQr9pwT0hw-F5UamYwuTs5SEcvSgF7lIBHtqLgWG-mEMvsr22PApk9UQ9bC32bk6MgATc4JvvHR9doMvc9ZN2wYQk9jpPFEERI1w9WuRYpDmg2YyU1C3RZJt37XcdffHKZP7M5TX1ikyVls2ELlfm8H1iw97IUUp9EAFAurQIdrrHpkc";
        String invalidSubjectJwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleUlkIn0.eyJzdWIiOiJ1c2VyYWRtaW4iLCJpc3MiOiJodHRwczovL2F0aGVuei5pbyIsImF1ZCI6Imh0dHBzOi8vem1zLmF0aGVuei5pbyIsInNjb3BlIjoic3lzLmF1dGg6cm9sZS5hZG1pbiIsImNsaWVudF9pZCI6InVpLmF0aGVuei5pbyIsImlhdCI6MTUxNjIzOTAyMiwiY25mIjp7Ing1dCNTMjU2IjoiemxreHlvWDk1bGUtTnY3T0kwQnhjalRPb2d2eTlQR0gtdl9DQnJfRHNFayJ9LCJleHAiOjk5OTAwMDk5OTl9.cyDB9uUdrG6qZI9D5nAW918fMHKFJSTcGSw1d3k6TRjvv-zqV_Wv1iO0vhGNVK0GVtoJwcAFDWL1ijVUx0v4o_L2esIBWPH5p-F-RtdVEoJ9cYU4Z2sVluUJ5p39UVlv2311gOmPC9q977m7myR7Cg4huTdzlHtiSN-d3bqppI3NhVd_gbol_bM1p2OiT301ItWYs2naSjWp2b-xTdBOIjV9UI5bpXGaLr_3lmfrm4jWfrfXzkmiZ4R1GdDtMYvkeCoss3UhrIjsm1snXPs-TPwrXAHz18sX53cFNciUZsXmiMdlOUo2sou0KfSRRWdHPP5ZFr9-UM-I355UHGMbR9SQmbIdE2zoXf8js_RAlOyHydB0vGBT5cszfsRPXL8mfBb8WURko3tNbCLavluHtiNFvK6WO2IrrJAe0VHChfkIlMBHcnB7wJIttrRuT4PKavJo8QKRgKUWgvQaMwE_g3eSNwBtVIbcM1d6d89JGvJ0DyqckimOhUHksReO1Aj-H3KO4yx705dVtZwDwPmFRvWvNNyuAvI3aIBVTO5-7XdL0zz6bsM8QeN4a_Gi0t1rUTp2TeWWHWwXb_TJ31FD74GGdaLodIpYKHNZ46oaZ7m5sX24AqFrragoLf3OA34vJ0fI3FwHZgUl6VuTH5dnvNBQ4arE7UfIExg8JyB1aXM";
        String customJwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleUlkIn0.eyJzdWIiOiJ1c2VyLmFkbWluIiwiaXNzIjoiY3VzdG9tLmlzcyIsImF1ZCI6WyJjdXN0b21fYXVkXzEiLCJjdXN0b21fYXVkXzIiXSwic2NvcGUiOiJjdXN0b21fc2NvcGVfMSBjdXN0b21fc2NvcGVfMiIsImNsaWVudF9pZCI6InVpLmF0aGVuei5pbyIsImlhdCI6MTUxNjIzOTAyMiwiY25mIjp7Ing1dCNTMjU2IjoiemxreHlvWDk1bGUtTnY3T0kwQnhjalRPb2d2eTlQR0gtdl9DQnJfRHNFayJ9LCJleHAiOjk5OTAwMDk5OTl9.Y7yRfrRB5xAe_9SpjnLuO1ULexEzdbT1PIR_lulRtNvBn9PzY1paBL14eSuPPFCDkP_250iWCrIkjAvis-xU42_ec8s8u6PmcCb7ziDca0TWjPsR0yd00CaJyecpnTVBF-U4RrhZ1GydajUh7y5IGTiXIZ4UsbzqAIPD7t5SfLdZ7ZApmdMH0lh1A5Vly8uoqlk2RKtJR7WcemrsL30zEAcmcjBPlVU_jvR8VUWOKMnKdoI8lW6uEvvi9mKKqeX2dhhf7oXusBTe6jlIikQwDqFeZw0BY9nskD8HBdwEpMSBNePF8exDRUzdmMAR5HSvnltjV2rZIm5zRBHdWnMXIeRfEflVIzLZnjeOhEitr-nN2KoeZnJL6-vpmHjPOXvyAzStrnngTezrVlyxoQn-IL8QUszZYusEE5kJ3MFiCB-ughXvdKlkxAgj10WNosxaVcbH9DCMkurXHaZD0yKmLkNDzjv7PkHNjrnxxMCy1Wh2t7nNRriM77s8Sf29ewv3YpiSWjzBmIoWAilS9WNBhduBa8jgQTRW9k0JhYkq6Z2fxjXVqkxLUsGwry8rIqAXltLUUPJ3O6DrsgOALvgOquBBJPsH5PgLSqKsaG2GnBykPgFcCWWhdU6Ue-B4YzgTTcDIu0IJ-XROtpxhAJDPLwS1MvxVLIo-K7uHB_aAM-Y";
        HttpServletRequest requestMock = null;
        StringBuilder errMsg = new StringBuilder();
        OAuthCertBoundJwtAccessTokenAuthority authority = new OAuthCertBoundJwtAccessTokenAuthority();
        authority.initialize();
        KeyStore jwtKeyStore = Mockito.spy(baseKeyStore);
        Mockito.when(jwtKeyStore.getPublicKey("", "", "keyId")).thenReturn(this.jwtPublicKey);
        authority.setKeyStore(jwtKeyStore);
        Principal principal = null;

        // empty token, skip
        requestMock = Mockito.mock(HttpServletRequestWrapper.class);
        Mockito.when(requestMock.getHeaders("Authorization")).thenReturn(Collections.enumeration(Arrays.asList()));
        errMsg.setLength(0);
        assertEquals(authority.authenticate(requestMock, errMsg), null);
        assertEquals(errMsg.length(), 0);

        // no certificate error
        requestMock = Mockito.mock(HttpServletRequestWrapper.class);
        Mockito.when(requestMock.getHeaders("Authorization")).thenReturn(Collections.enumeration(Arrays.asList("Bearer dummy_access_token")));
        errMsg.setLength(0);
        assertEquals(authority.authenticate(requestMock, errMsg), null);
        assertEquals(errMsg.toString(), "OAuthCertBoundJwtAccessTokenAuthority:authenticate: invalid certificate: No certificate available in request");

        // null errMsg, no errors
        requestMock = Mockito.mock(HttpServletRequestWrapper.class);
        Mockito.when(requestMock.getHeaders("Authorization")).thenReturn(Collections.enumeration(Arrays.asList("Bearer dummy_access_token_1")));
        assertEquals(authority.authenticate(requestMock, null), null);

        // parse JWT error
        requestMock = Mockito.mock(HttpServletRequestWrapper.class);
        Mockito.when(requestMock.getHeaders("Authorization")).thenReturn(Collections.enumeration(Arrays.asList("Bearer invalid_access_token")));
        Mockito.when(requestMock.getAttribute("javax.servlet.request.X509Certificate")).thenReturn(clientCertChain);
        errMsg.setLength(0);
        assertEquals(authority.authenticate(requestMock, errMsg), null);
        assertEquals(errMsg.toString(), "OAuthCertBoundJwtAccessTokenAuthority:authenticate: invalid JWT: io.jsonwebtoken.MalformedJwtException: JWT strings must contain exactly 2 period characters. Found: 0");
        requestMock = Mockito.mock(HttpServletRequestWrapper.class);
        Mockito.when(requestMock.getHeaders("Authorization")).thenReturn(Collections.enumeration(Arrays.asList("Bearer " + expiredJwt)));
        Mockito.when(requestMock.getAttribute("javax.servlet.request.X509Certificate")).thenReturn(clientCertChain);
        errMsg.setLength(0);
        assertEquals(authority.authenticate(requestMock, errMsg), null);
        assertTrue(errMsg.toString().startsWith("OAuthCertBoundJwtAccessTokenAuthority:authenticate: invalid JWT: io.jsonwebtoken.ExpiredJwtException: JWT expired at 2018-01-18T01:30:22Z. Current time: "));

        // invalid JWT
        requestMock = Mockito.mock(HttpServletRequestWrapper.class);
        Mockito.when(requestMock.getHeaders("Authorization")).thenReturn(Collections.enumeration(Arrays.asList("Bearer " + noExpJwt)));
        Mockito.when(requestMock.getAttribute("javax.servlet.request.X509Certificate")).thenReturn(clientCertChain);
        errMsg.setLength(0);
        assertEquals(authority.authenticate(requestMock, errMsg), null);
        assertEquals(errMsg.toString(), "OAuthCertBoundJwtAccessTokenAuthority:authenticate: invalid JWT: exp is empty");
        requestMock = Mockito.mock(HttpServletRequestWrapper.class);
        Mockito.when(requestMock.getHeaders("Authorization")).thenReturn(Collections.enumeration(Arrays.asList("Bearer " + noCnfJwt)));
        Mockito.when(requestMock.getAttribute("javax.servlet.request.X509Certificate")).thenReturn(clientCertChain);
        errMsg.setLength(0);
        assertEquals(authority.authenticate(requestMock, errMsg), null);
        assertEquals(errMsg.toString(), "OAuthCertBoundJwtAccessTokenAuthority:authenticate: invalid JWT: client certificate thumbprint (zlkxyoX95le-Nv7OI0BxcjTOogvy9PGH-v_CBr_DsEk) not match: got=null");

        // skip cert thumbprint verification
        System.setProperty("athenz.auth.oauth.jwt.verify_cert_thumbprint", "false");
        authority.initialize();
        System.clearProperty("athenz.auth.oauth.jwt.verify_cert_thumbprint");
        requestMock = Mockito.mock(HttpServletRequestWrapper.class);
        Mockito.when(requestMock.getHeaders("Authorization")).thenReturn(Collections.enumeration(Arrays.asList("Bearer " + noCnfJwt)));
        Mockito.when(requestMock.getAttribute("javax.servlet.request.X509Certificate")).thenReturn(clientCertChain);
        errMsg.setLength(0);
        principal = authority.authenticate(requestMock, errMsg);
        assertNotNull(principal);
        assertEquals(errMsg.toString(), "");
        assertEquals(principal.getDomain(), "user");
        assertEquals(principal.getName(), "admin");
        assertEquals(principal.getCredentials(), noCnfJwt);
        assertEquals(principal.getIssueTime(), 1516239022L);
        assertEquals(principal.getX509Certificate(), clientCertChain[0]);
        assertEquals(principal.getRoles(), null);
        assertEquals(principal.getApplicationId(), "ui.athenz.io");
        assertEquals(principal.getAuthorizedService(), "ui.athenz.io");
        authority.initialize(); // reset

        // invalid subject JWT
        requestMock = Mockito.mock(HttpServletRequestWrapper.class);
        Mockito.when(requestMock.getHeaders("Authorization")).thenReturn(Collections.enumeration(Arrays.asList("Bearer " + invalidSubjectJwt)));
        Mockito.when(requestMock.getAttribute("javax.servlet.request.X509Certificate")).thenReturn(clientCertChain);
        errMsg.setLength(0);
        assertEquals(authority.authenticate(requestMock, errMsg), null);
        assertEquals(errMsg.toString(), "OAuthCertBoundJwtAccessTokenAuthority:authenticate: sub is not a valid service identity: got=useradmin");

        // verify non-default JWT
        System.setProperty("athenz.auth.oauth.jwt.client_id_map_path", this.classLoader.getResource("client_map_ids.single.txt").getPath());
        System.setProperty("athenz.auth.oauth.jwt.claim.iss", "custom.iss");
        System.setProperty("athenz.auth.oauth.jwt.claim.aud", "custom_aud_1,custom_aud_2");
        System.setProperty("athenz.auth.oauth.jwt.claim.scope", "custom_scope_1 custom_scope_2");
        authority.initialize();
        System.clearProperty("athenz.auth.oauth.jwt.client_id_map_path");
        System.clearProperty("athenz.auth.oauth.jwt.claim.iss");
        System.clearProperty("athenz.auth.oauth.jwt.claim.aud");
        System.clearProperty("athenz.auth.oauth.jwt.claim.scope");
        requestMock = Mockito.mock(HttpServletRequestWrapper.class);
        Mockito.when(requestMock.getHeaders("Authorization")).thenReturn(Collections.enumeration(Arrays.asList("Bearer " + customJwt)));
        Mockito.when(requestMock.getAttribute("javax.servlet.request.X509Certificate")).thenReturn(clientCertChain);
        errMsg.setLength(0);
        principal = authority.authenticate(requestMock, errMsg);
        assertNotNull(principal);
        assertEquals(errMsg.toString(), "");
        assertEquals(principal.getDomain(), "user");
        assertEquals(principal.getName(), "admin");
        assertEquals(principal.getCredentials(), customJwt);
        assertEquals(principal.getIssueTime(), 1516239022L);
        assertEquals(principal.getX509Certificate(), clientCertChain[0]);
        assertEquals(principal.getRoles(), null);
        assertEquals(principal.getApplicationId(), "ui.athenz.io");
        assertEquals(principal.getAuthorizedService(), "sys.auth.ui");
        authority.initialize(); // reset

    }

}
