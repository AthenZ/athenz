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
package com.yahoo.athenz.auth.oauth;

import static org.testng.Assert.*;

import java.io.FileInputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
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
    public void testGetCredSource() {
        OAuthCertBoundJwtAccessTokenAuthority authority = new OAuthCertBoundJwtAccessTokenAuthority();
        assertEquals(authority.getCredSource(), CredSource.REQUEST);
    }

    @Test
    public void testGetAuthenticateChallenge() {
        OAuthCertBoundJwtAccessTokenAuthority authority = new OAuthCertBoundJwtAccessTokenAuthority();
        assertEquals(authority.getAuthenticateChallenge(), "Bearer realm=\"athenz.io\"");
    }

    @Test
    public void testGetDomain() throws Exception {
        OAuthCertBoundJwtAccessTokenAuthority authority = new OAuthCertBoundJwtAccessTokenAuthority();
        assertNull(authority.getDomain());
    }

    @Test
    public void testGetHeader() {
        OAuthCertBoundJwtAccessTokenAuthority authority = new OAuthCertBoundJwtAccessTokenAuthority();
        assertEquals(authority.getHeader(), "Authorization");
    }

    @Test
    public void testAuthenticateWithHeader() {
        OAuthCertBoundJwtAccessTokenAuthority authority = new OAuthCertBoundJwtAccessTokenAuthority();
        assertNull(authority.authenticate(null, null, null, null));
    }

    @Test
    public void testProcessAuthorizedClientIds() throws Exception {
        OAuthCertBoundJwtAccessTokenAuthority authority = new OAuthCertBoundJwtAccessTokenAuthority();
        Method processAuthorizedClientIds = authority.getClass().getDeclaredMethod("processAuthorizedClientIds", String.class, Map.class, Map.class);
        processAuthorizedClientIds.setAccessible(true);
        Map<String, Set<String>> authorizedClientIds = new HashMap<>();
        Map<String, String> authorizedServices = new HashMap<>();

        // empty args
        processAuthorizedClientIds.invoke(authority, null, authorizedClientIds, authorizedServices);
        assertEquals(authorizedClientIds.size(), 0);
        assertEquals(authorizedServices.size(), 0);
        authorizedClientIds.clear();
        authorizedServices.clear();
        processAuthorizedClientIds.invoke(authority, "", authorizedClientIds, authorizedServices);
        assertEquals(authorizedClientIds.size(), 0);
        assertEquals(authorizedServices.size(), 0);

        // no such file
        String non_existing_filepath = this.classLoader.getResource("authorized_client_ids.empty.txt").toURI().resolve("./authorized_client_ids.non_existing.txt").getPath();
        authorizedClientIds.clear();
        authorizedServices.clear();
        processAuthorizedClientIds.invoke(authority, non_existing_filepath, authorizedClientIds, authorizedServices);
        assertEquals(authorizedClientIds.size(), 0);
        assertEquals(authorizedServices.size(), 0);

        // empty file
        authorizedClientIds.clear();
        authorizedServices.clear();
        processAuthorizedClientIds.invoke(authority, this.classLoader.getResource("authorized_client_ids.empty.txt").getPath(), authorizedClientIds, authorizedServices);
        assertEquals(authorizedClientIds.size(), 0);
        assertEquals(authorizedServices.size(), 0);

        // authorized_client_ids.txt
        authorizedClientIds.clear();
        authorizedServices.clear();
        Map<String, Set<String>> expectedAuthorizedClientIds = new HashMap<>();
        Map<String, String> expectedAuthorizedServices = new HashMap<>();
        expectedAuthorizedClientIds.put("ui_principal_11", new HashSet<>(Arrays.asList("client_id_11","client_id_12")));
        expectedAuthorizedServices.put("ui_principal_11", "authorized_service_11");
        expectedAuthorizedClientIds.put("ui_principal_21", new HashSet<>(List.of("client_id_21")));
        expectedAuthorizedServices.put("ui_principal_21", "authorized_service_21");
        expectedAuthorizedClientIds.put("ui_principal_31", new HashSet<>(Arrays.asList("client_id_31")));
        expectedAuthorizedServices.put("ui_principal_31", "authorized_service_31");
        expectedAuthorizedClientIds.put("ui_principal_41", new HashSet<>(Arrays.asList("client_id_41","trailing_comma")));
        expectedAuthorizedServices.put("ui_principal_41", "authorized_service_41");
        processAuthorizedClientIds.invoke(authority, this.classLoader.getResource("authorized_client_ids.txt").getPath(), authorizedClientIds, authorizedServices);
        assertEquals(authorizedClientIds, expectedAuthorizedClientIds);
        assertEquals(authorizedServices, expectedAuthorizedServices);
    }

    static final class OAuthCertBoundJwtAccessTokenAuthorityTestParser implements OAuthJwtAccessTokenParser {
        @Override
        public OAuthJwtAccessToken parse(String jwtString) {
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
        Field certificateIdentityParserField = authority.getClass().getDeclaredField("certificateIdentityParser");
        certificateIdentityParserField.setAccessible(true);

        System.setProperty("athenz.auth.oauth.jwt.cert.exclude_role_certificates", "true");
        System.setProperty("athenz.auth.oauth.jwt.cert.excluded_principals", "principals_1,principals_2");
        authority.initialize();
        System.clearProperty("athenz.auth.oauth.jwt.cert.exclude_role_certificates");
        System.clearProperty("athenz.auth.oauth.jwt.cert.excluded_principals");
        CertificateIdentityParser certParser = (CertificateIdentityParser) certificateIdentityParserField.get(authority);
        Field excludeRoleCertificatesField  = certParser.getClass().getDeclaredField("excludeRoleCertificates");
        Field excludedPrincipalsField  = certParser.getClass().getDeclaredField("excludedPrincipalSet");
        excludeRoleCertificatesField.setAccessible(true);
        excludedPrincipalsField.setAccessible(true);
        assertEquals(excludeRoleCertificatesField.get(certParser), true);
        assertEquals(excludedPrincipalsField.get(certParser), new HashSet<>(Arrays.asList("principals_1", "principals_2")));

        System.clearProperty("athenz.auth.oauth.jwt.cert.exclude_role_certificates");
        System.clearProperty("athenz.auth.oauth.jwt.cert.excluded_principals");
        authority.initialize();
        certParser = (CertificateIdentityParser) certificateIdentityParserField.get(authority);
        excludeRoleCertificatesField  = certParser.getClass().getDeclaredField("excludeRoleCertificates");
        excludedPrincipalsField  = certParser.getClass().getDeclaredField("excludedPrincipalSet");
        excludeRoleCertificatesField.setAccessible(true);
        excludedPrincipalsField.setAccessible(true);
        assertEquals(excludeRoleCertificatesField.get(certParser), false);
        assertNull(excludedPrincipalsField.get(certParser));

        // parser
        Field parserField = authority.getClass().getDeclaredField("parser");
        parserField.setAccessible(true);

        System.setProperty("athenz.auth.oauth.jwt.parser_factory_class", "invalid_class");
        assertThrows(IllegalArgumentException.class, authority::initialize);
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

        // authorizedServices & validator
        Field authorizedServicesField = authority.getClass().getDeclaredField("authorizedServices");
        authorizedServicesField.setAccessible(true);
        Field validatorField = authority.getClass().getDeclaredField("validator");
        validatorField.setAccessible(true);

        System.setProperty("athenz.auth.oauth.jwt.authorized_client_ids_path", "");
        System.setProperty("athenz.auth.oauth.jwt.claim.iss", "");
        System.setProperty("athenz.auth.oauth.jwt.claim.aud", "");
        System.setProperty("athenz.auth.oauth.jwt.claim.scope", "");
        assertThrows(IllegalArgumentException.class, authority::initialize);
        System.clearProperty("athenz.auth.oauth.jwt.authorized_client_ids_path");
        System.clearProperty("athenz.auth.oauth.jwt.claim.iss");
        System.clearProperty("athenz.auth.oauth.jwt.claim.aud");
        System.clearProperty("athenz.auth.oauth.jwt.claim.scope");

        Map<String, String> expectedAuthorizedServices = new HashMap<>();
        Map<String, Set<String>> expectedAuthorizedClientIds = new HashMap<>();
        expectedAuthorizedServices.put("ui.athenz.io", "sys.auth.ui");
        expectedAuthorizedClientIds.put("ui.athenz.io", new HashSet<>(Arrays.asList("client_id_1","client_id_2","ui.athenz.io")));
        System.setProperty("athenz.auth.oauth.jwt.authorized_client_ids_path", this.classLoader.getResource("authorized_client_ids.single.txt").getPath());
        System.setProperty("athenz.auth.oauth.jwt.claim.iss", "iss");
        System.setProperty("athenz.auth.oauth.jwt.claim.aud", "aud_1,aud_2");
        System.setProperty("athenz.auth.oauth.jwt.claim.scope", "scope_1 scope_2");
        authority.initialize();
        System.clearProperty("athenz.auth.oauth.jwt.authorized_client_ids_path");
        System.clearProperty("athenz.auth.oauth.jwt.claim.iss");
        System.clearProperty("athenz.auth.oauth.jwt.claim.aud");
        System.clearProperty("athenz.auth.oauth.jwt.claim.scope");
        assertEquals(authorizedServicesField.get(authority), expectedAuthorizedServices);
        DefaultOAuthJwtAccessTokenValidator validator = (DefaultOAuthJwtAccessTokenValidator) validatorField.get(authority);
        Field trustedIssuerField = validator.getClass().getDeclaredField("trustedIssuer");
        Field requiredAudiencesField = validator.getClass().getDeclaredField("requiredAudiences");
        Field requiredScopesField = validator.getClass().getDeclaredField("requiredScopes");
        Field authorizedClientIdsField = validator.getClass().getDeclaredField("authorizedClientIds");
        trustedIssuerField.setAccessible(true);
        requiredAudiencesField.setAccessible(true);
        requiredScopesField.setAccessible(true);
        authorizedClientIdsField.setAccessible(true);
        assertEquals(trustedIssuerField.get(validator), "iss");
        assertEquals(requiredAudiencesField.get(validator), new HashSet<>(Arrays.asList("aud_1", "aud_2")));
        assertEquals(requiredScopesField.get(validator), new HashSet<>(Arrays.asList("scope_1", "scope_2")));
        assertEquals(authorizedClientIdsField.get(validator), expectedAuthorizedClientIds);

        System.clearProperty("athenz.auth.oauth.jwt.authorized_client_ids_path");
        System.clearProperty("athenz.auth.oauth.jwt.claim.iss");
        System.clearProperty("athenz.auth.oauth.jwt.claim.aud");
        System.clearProperty("athenz.auth.oauth.jwt.claim.scope");
        authority.initialize();
        assertEquals(authorizedServicesField.get(authority), new HashMap<String, String>());
        validator = (DefaultOAuthJwtAccessTokenValidator) validatorField.get(authority);
        trustedIssuerField = validator.getClass().getDeclaredField("trustedIssuer");
        requiredAudiencesField = validator.getClass().getDeclaredField("requiredAudiences");
        requiredScopesField = validator.getClass().getDeclaredField("requiredScopes");
        authorizedClientIdsField = validator.getClass().getDeclaredField("authorizedClientIds");
        trustedIssuerField.setAccessible(true);
        requiredAudiencesField.setAccessible(true);
        requiredScopesField.setAccessible(true);
        authorizedClientIdsField.setAccessible(true);
        assertEquals(trustedIssuerField.get(validator), "https://athenz.io");
        assertEquals(requiredAudiencesField.get(validator), new HashSet<>(Arrays.asList("https://zms.athenz.io")));
        assertEquals(requiredScopesField.get(validator), new HashSet<>(Arrays.asList("sys.auth:role.admin")));
        assertEquals(authorizedClientIdsField.get(validator), new HashMap<String, String>());
    }

    @Test
    public void testAuthenticate() {
        String expiredJwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleUlkIn0.eyJzdWIiOiJ1c2VyLmFkbWluIiwiaXNzIjoic3lzLmF1dGgudGVzdElkUCIsImF1ZCI6Imh0dHBzOi8vem1zLmF0aGVuei5pbyIsInNjb3BlIjoic3lzLmF1dGg6cm9sZS5hZG1pbiIsImNsaWVudF9pZCI6InVpLmF0aGVuei5pbyIsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxNTE2MjM5MDIyfQ.cMbo1Ogwz3HTGdfncjBn3H99ehe_yT1Zhlb8vmDqvPnbjuZUnuFl3aZEIE_JyLQrGADZf9PFlqxMNQcd_AlrZ-SePW8u4kIe1mFBr6oSTzuBkLzpwlff_vWaoOGlXrjlai64ISaDXYaYFPxnNMhjFSpod6D_anaQqs3XXEqrlwHHG7zk99UvPZehtXntKcAv0it8K5_7-vtQiEqHIvy14oxLNhQa801bhaUvjgnSVhnQzfXTCYzM4B1QfF1Cp7k9ktw3tsOShZGYHYr-XOvO_199z0ZJfWkdqk_FA3Mdo_Nw_r9ghh2kCx5YhmNpaqN9BANmwv3PbREcfIt1o4V7ZTHSzBq2cuCjEmU59Nl530tUMe31npw-8i6MIGzE_Ifg4k5ea1L1JBzQkbtWeIVd8SV3j_D0TNhYmeeAYgK8UikkFIw3Uza6ZvfZKTe8cffomzzfeB5fjL9GUsqj6LpIL1R2CgCQARqlZDGl9d73j81G7r7qZPZuBW5U3c3cPrdChw1-AwgDT27-Hu3yAzxZyJmsfIkUj5VZZfb1loIsovcRr_h9VUeNEqMimKfwxRBr7EP7fw7eRQoAJIthdeMGS6hfh-ZPM85N2YN34aQ0YJKWJUgdLudCGpkmfYBBd28D1VGNTUlfEuwHXosVP1GoYLXlz8zgwWIoXuk_bj4QH-g";
        String noExpJwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleUlkIn0.eyJzdWIiOiJ1c2VyLmFkbWluIiwiaXNzIjoic3lzLmF1dGgudGVzdElkUCIsImF1ZCI6Imh0dHBzOi8vem1zLmF0aGVuei5pbyIsInNjb3BlIjoic3lzLmF1dGg6cm9sZS5hZG1pbiIsImNsaWVudF9pZCI6InVpLmF0aGVuei5pbyIsImlhdCI6MTUxNjIzOTAyMn0.I8da4Q_SysUJ3O4VZQQb7v0tQHNaAWk7WGkC3AImhd6FK_g6wAFe4Nw7K5ofOCdJKjHGUmqgBpnt1vbOqia8UJhcKkByBXywVnbK655MQ3ogkBmi3tUPx6Dmq1dwiaxsVZMAnxFQeACcTEz_Q_BWiXJqSpUP0vBy2sOFTus_xmvcooewu7n-EgdrO26oYwCMp0IARaSZq6hRmF5Le4wyz8d8CEzIArjEBOBpbONsX3NOvPSox3whDvIk91Zy4ZsORAMoLgGSQTqrEYBLSsFwng01V_OW4JVfM2p9f3U2gpqF6Ja7FFXrxnrgXEjvLvcMQYgv21eTT7ELMMFFQaYLPcCXNDoGwPOOU0dxngqw9B9qqhZV-gTJ7w5ADH2knwqNN5EJxnflVU_D-dUZFNJ0ruMc3bfsLzXQhhHqdhY6h6vkqQ2IGUiGilS4hgVWa26QOstj1twf4Dj1xaHro5800evW886pwJyK3FSfULrvpiJ6Q_DkzSEG1sGRj4RTwl8Opgh27Mot5m2x-qESwbEMeazz2saIdHpt6lcH1VY2baazy322mCRXzA9SdQD-u2bjjI4Fu-AJQRbL51pvzNceXJdz9xwnbX5RgY99E6AYOlzQ5zVl7PDsxLwdJr8UppYGQmrTBZ7DBjtNXGGMelZ0M1SBJVa0JZ3K61MWnYzPL5M";
        String noCnfJwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleUlkIn0.eyJzdWIiOiJ1c2VyLmFkbWluIiwiaXNzIjoic3lzLmF1dGgudGVzdElkUCIsImF1ZCI6Imh0dHBzOi8vem1zLmF0aGVuei5pbyIsInNjb3BlIjoic3lzLmF1dGg6cm9sZS5hZG1pbiIsImNsaWVudF9pZCI6InVpLmF0aGVuei5pbyIsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjo5OTkwMDA5OTk5fQ.uE-SsyDGb0a1QU1Clv0WmwZqIm1HXc0pJy_rGofpIeo5jOsz3wj1ZVjGslgLV56hW9zvnwOh5ur8ChgQrYfDN1meM6loiu4py9mAU9bfaiPkecqGA5zmWQjhl9206MbVKxFXbVlt5FrQJaM5corSkIH4MIpxS4vU2dZBC4Emtc8hZXRg5BOKr6xRA-vTLbWNa3FTh8dhehTXngQ_bnJfU5MxoTMlrBCrajKjnzSYzZ6vutJKDZKGdbmRrM982wjuDyEzhViKVDBsNqUa0LUblBoUtVx2FnPCUlBWnyqm4aaf6FtqV8z2KolcH1DA_3PaWv1R_txFD0B4pRm1GA77LGCgAdNzZ4KMBN300K0DzBhbYS4fmbr0faAIUtYWRTI3PwkSQGUwZTS4FZbK6RQ-kUkx68BhLP3R33E06EGsb7qvdcPELFjMh8HtbUPUZdJnq0z5Q6EJrWE4h3_7c6JDCm5IIJ9GDN8u20l0BFQe1SCmcYAVutuuGX_79B73r2sQdm8-6LVoOZXtDFLlbadcXUHybUgZYYSlehKD1Vdt4JQqeVStdUM0q7Otfe9dhfrDHwJrEN9iGNWVItxlP86K8SrTRzaa8b1Qs6E-qXx_6XFF3taFU9jWS3I571WrXo1qkJp6QQknqEFa1JJkh28UDjonkgRSzeProQxbF_7T5VE";
        String invalidSubjectJwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleUlkIn0.eyJzdWIiOiJ1c2VyYWRtaW4iLCJpc3MiOiJzeXMuYXV0aC50ZXN0SWRQIiwiYXVkIjoiaHR0cHM6Ly96bXMuYXRoZW56LmlvIiwic2NvcGUiOiJzeXMuYXV0aDpyb2xlLmFkbWluIiwiY2xpZW50X2lkIjoidWkuYXRoZW56LmlvIiwiaWF0IjoxNTE2MjM5MDIyLCJjbmYiOnsieDV0I1MyNTYiOiJ6bGt4eW9YOTVsZS1OdjdPSTBCeGNqVE9vZ3Z5OVBHSC12X0NCcl9Ec0VrIn0sImV4cCI6OTk5MDAwOTk5OX0.HhCeOzNcDtR6GmPvlARwn5NSNPK3QhLw_LSsyg8LIq35vu8BoBsgX-Dw8GuFXc84e9gFdV5LTPOpOM78Ktc_L-eQ27j3u_UggCGwxkZHknRprLzBDx8A-bM3VyPyxTpokNFyrmrDbUn7pE8QwDRuPxOHjZUG1Wca2kY9YtgxnvYmh8w6TRH_uKdCPlbdo6FgQFbpSXZWbm0_UOQXpsSLH-q9vwz52D2wuDM_kGigLf1GKueshj-4Rzmrgh1nT-Zb6JQtBKdsnJRjQi9O9gQFwAdUcFFLVXd8IQKpgJc6ZvesGBwJmEOrE-THFHaGPdiRbqgMc8ha_0uknVeOwgiIflQfXi2Tid6aXBWBLDnABJuzlpSs7cXto3Fu-RAQLCQ16YJnFfeaCpmRkkjqTIupgRUy3_rqBNDUgg62kGjb6Sz_Q9lC1rdvx19i2lZqlvxgX1Q0_tbkqfCXm4mgU8b70OJ2oVGE6fq4hXDIKl-v7YAtDQdfqz3OmN6epRdOXCi3ZdgE5QzJS1TVbu-IgGrNgkfl8QzS02mSoIUpJAWZfE_21oYvLNjtYuOC2r9q3CSTwUHQJu45HupZnr0dLq7dIV-y_PAanHpz2IRJrhbZBicbR2P0sBsx-FxPUIGCK4II3Gsx5LehYNWYHSNnzdaGZC56x41VTzo2g7KNqLNYUBk";
        String customJwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleUlkIn0.eyJzdWIiOiJ1c2VyLmFkbWluIiwiaXNzIjoic3lzLmF1dGgudGVzdElkUCIsImF1ZCI6WyJjdXN0b21fYXVkXzEiLCJjdXN0b21fYXVkXzIiXSwic2NvcGUiOiJjdXN0b21fc2NvcGVfMSBjdXN0b21fc2NvcGVfMiIsImNsaWVudF9pZCI6InVpLmF0aGVuei5pbyIsImlhdCI6MTUxNjIzOTAyMiwiY25mIjp7Ing1dCNTMjU2IjoiemxreHlvWDk1bGUtTnY3T0kwQnhjalRPb2d2eTlQR0gtdl9DQnJfRHNFayJ9LCJleHAiOjk5OTAwMDk5OTl9.HCc0RCeV06gtgUKPoSDGhFySDxsCujmpzbge-oe1YQv43sRBTJfvJ4JIDnuPCosPugw8R9l9Bj3VM_sKSLHpJGhDRcQPamlawdes7bHSSL8VDoQIPLIzTdQUXc81OJqKSTMBjChdPzHSKF3VpwnrMpuFuBLvPs7PyN7xXxzDlEANPYx6-9pnd_z_eB4hABj0Q_fyX9pcm9wyXPyW3eEDo0m_R80fa6CUaEGt6FseVyZp7WimCXF-IongjXJLy3BLppVIUHg5U_rVmvoe81pE7-tJe7NiS5suUWLq-kMBNhmGBulGNLbH8VT4jOVDTpzS8a3jHL18xtHlij9Zbg4zpBbo4Z8O0Az37SS1vrGwTMPAW9uhjVRqAJB1MM5YZ5Rr8XRy6hduF-FbDmOP27jE_n0Hk2oQ2yfaB2oAY0wjpSLukV_CNzaDWrBBu_j25ld1OsvKeHXTBtf8EhjIcWrktu48SJvoDNQZZskeDXAt7gabFv7y2Gbe4JG4AF43-ewRuFzoMBJsLgzjvd7f1v71leTV519AD4ScjJNp17PakSc8BFu3E9--yr2jLFsJ1cC3VtezdOV2Jssh00WiklsB-mdcHi2WOXr3XONuix6ZvS2DehQCKEFtGEQcWe3oLjZmE5QDJNvuCbU1GbtAXiAbbEuqKaUKUf9HZW2KVfUSgqI";
        StringBuilder errMsg = new StringBuilder();
        OAuthCertBoundJwtAccessTokenAuthority authority = new OAuthCertBoundJwtAccessTokenAuthority();
        System.setProperty("athenz.auth.oauth.jwt.claim.iss", "sys.auth.testIdP");
        authority.initialize();
        System.clearProperty("athenz.auth.oauth.jwt.claim.iss");
        KeyStore jwtKeyStore = Mockito.spy(baseKeyStore);
        Mockito.when(jwtKeyStore.getPublicKey("sys.auth", "testidp", "keyId")).thenReturn(this.jwtPublicKey);
        authority.setKeyStore(jwtKeyStore);

        // empty token, skip
        HttpServletRequest requestMock = Mockito.mock(HttpServletRequestWrapper.class);
        Mockito.when(requestMock.getHeaders("Authorization")).thenReturn(Collections.enumeration(Arrays.asList()));
        errMsg.setLength(0);
        assertNull(authority.authenticate(requestMock, errMsg));
        assertEquals(errMsg.length(), 0);

        // no certificate error
        requestMock = Mockito.mock(HttpServletRequestWrapper.class);
        Mockito.when(requestMock.getHeaders("Authorization")).thenReturn(Collections.enumeration(Arrays.asList("Bearer dummy_access_token")));
        errMsg.setLength(0);
        assertNull(authority.authenticate(requestMock, errMsg));
        assertEquals(errMsg.toString(), "OAuthCertBoundJwtAccessTokenAuthority:authenticate: invalid certificate: No certificate available in request");

        // null errMsg, no errors
        requestMock = Mockito.mock(HttpServletRequestWrapper.class);
        Mockito.when(requestMock.getHeaders("Authorization")).thenReturn(Collections.enumeration(Arrays.asList("Bearer dummy_access_token_1")));
        assertNull(authority.authenticate(requestMock, null));

        // parse JWT error
        requestMock = Mockito.mock(HttpServletRequestWrapper.class);
        Mockito.when(requestMock.getHeaders("Authorization")).thenReturn(Collections.enumeration(Arrays.asList("Bearer invalid_access_token")));
        Mockito.when(requestMock.getAttribute(CertificateIdentityParser.JAVAX_CERT_ATTR)).thenReturn(clientCertChain);
        errMsg.setLength(0);
        assertNull(authority.authenticate(requestMock, errMsg));
        assertEquals(errMsg.toString(), "OAuthCertBoundJwtAccessTokenAuthority:authenticate: invalid JWT: io.jsonwebtoken.MalformedJwtException: JWT strings must contain exactly 2 period characters. Found: 0");
        requestMock = Mockito.mock(HttpServletRequestWrapper.class);
        Mockito.when(requestMock.getHeaders("Authorization")).thenReturn(Collections.enumeration(Arrays.asList("Bearer " + expiredJwt)));
        Mockito.when(requestMock.getAttribute(CertificateIdentityParser.JAVAX_CERT_ATTR)).thenReturn(clientCertChain);
        errMsg.setLength(0);
        assertNull(authority.authenticate(requestMock, errMsg));
        assertTrue(errMsg.toString().startsWith("OAuthCertBoundJwtAccessTokenAuthority:authenticate: invalid JWT: io.jsonwebtoken.ExpiredJwtException: JWT expired at 2018-01-18T01:30:22Z. Current time: "));

        // invalid JWT
        requestMock = Mockito.mock(HttpServletRequestWrapper.class);
        Mockito.when(requestMock.getHeaders("Authorization")).thenReturn(Collections.enumeration(Arrays.asList("Bearer " + noExpJwt)));
        Mockito.when(requestMock.getAttribute(CertificateIdentityParser.JAVAX_CERT_ATTR)).thenReturn(clientCertChain);
        errMsg.setLength(0);
        assertNull(authority.authenticate(requestMock, errMsg));
        assertEquals(errMsg.toString(), "OAuthCertBoundJwtAccessTokenAuthority:authenticate: invalid JWT: exp is empty");
        requestMock = Mockito.mock(HttpServletRequestWrapper.class);
        Mockito.when(requestMock.getHeaders("Authorization")).thenReturn(Collections.enumeration(Arrays.asList("Bearer " + noCnfJwt)));
        Mockito.when(requestMock.getAttribute(CertificateIdentityParser.JAVAX_CERT_ATTR)).thenReturn(clientCertChain);
        errMsg.setLength(0);
        assertNull(authority.authenticate(requestMock, errMsg));
        assertEquals(errMsg.toString(), "OAuthCertBoundJwtAccessTokenAuthority:authenticate: invalid JWT: NO mapping of authorized client IDs for certificate principal (ui.athenz.io)");

        // skip cert thumbprint verification
        System.setProperty("athenz.auth.oauth.jwt.authorized_client_ids_path", this.classLoader.getResource("authorized_client_ids.single.txt").getPath());
        System.setProperty("athenz.auth.oauth.jwt.verify_cert_thumbprint", "false");
        System.setProperty("athenz.auth.oauth.jwt.claim.iss", "sys.auth.testIdP");
        authority.initialize();
        System.clearProperty("athenz.auth.oauth.jwt.claim.iss");
        System.clearProperty("athenz.auth.oauth.jwt.authorized_client_ids_path");
        System.clearProperty("athenz.auth.oauth.jwt.verify_cert_thumbprint");
        requestMock = Mockito.mock(HttpServletRequestWrapper.class);
        Mockito.when(requestMock.getHeaders("Authorization")).thenReturn(Collections.enumeration(Arrays.asList("Bearer " + noCnfJwt)));
        Mockito.when(requestMock.getAttribute(CertificateIdentityParser.JAVAX_CERT_ATTR)).thenReturn(clientCertChain);
        errMsg.setLength(0);
        Principal principal = authority.authenticate(requestMock, errMsg);
        assertNotNull(principal);
        assertEquals(errMsg.toString(), "");
        assertEquals(principal.getDomain(), "user");
        assertEquals(principal.getName(), "admin");
        assertEquals(principal.getCredentials(), noCnfJwt);
        assertEquals(principal.getIssueTime(), 1516239022L);
        assertEquals(principal.getX509Certificate(), clientCertChain[0]);
        assertNull(principal.getRoles());
        assertEquals(principal.getApplicationId(), "ui.athenz.io");
        assertEquals(principal.getAuthorizedService(), "sys.auth.ui");
        System.setProperty("athenz.auth.oauth.jwt.claim.iss", "sys.auth.testIdP");
        authority.initialize(); // reset
        System.clearProperty("athenz.auth.oauth.jwt.claim.iss");

        // invalid subject JWT
        System.setProperty("athenz.auth.oauth.jwt.authorized_client_ids_path", this.classLoader.getResource("authorized_client_ids.single.txt").getPath());
        System.setProperty("athenz.auth.oauth.jwt.claim.iss", "sys.auth.testIdP");
        authority.initialize();
        System.clearProperty("athenz.auth.oauth.jwt.claim.iss");
        System.clearProperty("athenz.auth.oauth.jwt.authorized_client_ids_path");
        requestMock = Mockito.mock(HttpServletRequestWrapper.class);
        Mockito.when(requestMock.getHeaders("Authorization")).thenReturn(Collections.enumeration(Arrays.asList("Bearer " + invalidSubjectJwt)));
        Mockito.when(requestMock.getAttribute(CertificateIdentityParser.JAVAX_CERT_ATTR)).thenReturn(clientCertChain);
        errMsg.setLength(0);
        assertNull(authority.authenticate(requestMock, errMsg));
        assertEquals(errMsg.toString(), "OAuthCertBoundJwtAccessTokenAuthority:authenticate: sub is not a valid service identity: got=useradmin");

        // verify non-default JWT
        System.setProperty("athenz.auth.oauth.jwt.authorized_client_ids_path", this.classLoader.getResource("authorized_client_ids.single.txt").getPath());
        System.setProperty("athenz.auth.oauth.jwt.claim.iss", "custom.iss");
        System.setProperty("athenz.auth.oauth.jwt.claim.aud", "custom_aud_1,custom_aud_2");
        System.setProperty("athenz.auth.oauth.jwt.claim.scope", "custom_scope_1 custom_scope_2");
        System.setProperty("athenz.auth.oauth.jwt.claim.iss", "sys.auth.testIdP");
        authority.initialize();
        System.clearProperty("athenz.auth.oauth.jwt.claim.iss");
        System.clearProperty("athenz.auth.oauth.jwt.authorized_client_ids_path");
        System.clearProperty("athenz.auth.oauth.jwt.claim.iss");
        System.clearProperty("athenz.auth.oauth.jwt.claim.aud");
        System.clearProperty("athenz.auth.oauth.jwt.claim.scope");
        requestMock = Mockito.mock(HttpServletRequestWrapper.class);
        Mockito.when(requestMock.getHeaders("Authorization")).thenReturn(Collections.enumeration(Arrays.asList("Bearer " + customJwt)));
        Mockito.when(requestMock.getAttribute(CertificateIdentityParser.JAVAX_CERT_ATTR)).thenReturn(clientCertChain);
        errMsg.setLength(0);
        principal = authority.authenticate(requestMock, errMsg);
        assertNotNull(principal);
        assertEquals(errMsg.toString(), "");
        assertEquals(principal.getDomain(), "user");
        assertEquals(principal.getName(), "admin");
        assertEquals(principal.getCredentials(), customJwt);
        assertEquals(principal.getIssueTime(), 1516239022L);
        assertEquals(principal.getX509Certificate(), clientCertChain[0]);
        assertNull(principal.getRoles());
        assertEquals(principal.getApplicationId(), "ui.athenz.io");
        assertEquals(principal.getAuthorizedService(), "sys.auth.ui");
        System.setProperty("athenz.auth.oauth.jwt.claim.iss", "sys.auth.testIdP");
        authority.initialize(); // reset
        System.clearProperty("athenz.auth.oauth.jwt.claim.iss");

    }

}
