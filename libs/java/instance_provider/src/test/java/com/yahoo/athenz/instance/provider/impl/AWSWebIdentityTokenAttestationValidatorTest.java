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
package com.yahoo.athenz.instance.provider.impl;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;

import java.io.File;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class AWSWebIdentityTokenAttestationValidatorTest {

    private final ClassLoader classLoader = this.getClass().getClassLoader();
    private final File ecPrivateKey = new File("./src/test/resources/unit_test_ec_private.key");

    // an issuer that matches the default AWS STS issuer regex
    private static final String AWS_ISSUER = "https://a235ce0e-ece5-7bh3-b26c-62f78631444b.tokens.sts.global.api.aws";
    private static final String AUDIENCE = "https://zts.athenz.io/zts/v1";
    private static final String STS_CLAIM = "https://sts.amazonaws.com/";

    @AfterMethod
    public void shutdown() {
        System.clearProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_AUDIENCE);
        System.clearProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_ISSUER_REGEX);
        System.clearProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_ALLOWED_ORG_IDS);
        System.clearProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_STS_CLAIM_NAME);
        System.clearProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_PRINCIPAL_VALIDATOR_FACTORY_CLASS);
    }

    private String generateToken(final String issuer, final String audience, final String subject,
            final Map<String, Object> stsClaim) throws Exception {

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        JWSSigner signer = new ECDSASigner((ECPrivateKey) privateKey);

        long now = System.currentTimeMillis() / 1000;
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .expirationTime(Date.from(Instant.ofEpochSecond(now + 3600)))
                .issueTime(Date.from(Instant.ofEpochSecond(now)))
                .issuer(issuer)
                .audience(audience);
        if (subject != null) {
            builder.subject(subject);
        }
        if (stsClaim != null) {
            builder.claim(STS_CLAIM, stsClaim);
        }

        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("eckey1").build(),
                builder.build());
        signedJWT.sign(signer);
        return signedJWT.serialize();
    }

    private Map<String, Object> stsClaim(final String awsAccount, final String orgId) {
        Map<String, Object> claim = new HashMap<>();
        claim.put(AWSWebIdentityTokenAttestationValidator.STS_CLAIM_AWS_ACCOUNT, awsAccount);
        claim.put(AWSWebIdentityTokenAttestationValidator.STS_CLAIM_ORG_ID, orgId);
        return claim;
    }

    // a validator that resolves the issuer keys from the local test JWKS so the
    // (regex-matching) issuer needn't be network resolvable
    private AWSWebIdentityTokenAttestationValidator newValidator(Authorizer authorizer) {
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        AWSWebIdentityTokenAttestationValidator validator = new AWSWebIdentityTokenAttestationValidator() {
            @Override
            JwtsSigningKeyResolver getSigningKeyResolverForIssuer(String issuer, StringBuilder errMsg) {
                return new JwtsSigningKeyResolver(jwksUri, null, true);
            }
        };
        validator.initialize(null, authorizer);
        return validator;
    }

    private InstanceConfirmation confirmation() {
        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("athenz");
        confirmation.setService("api");
        confirmation.setAttributes(new HashMap<>());
        return confirmation;
    }

    @Test
    public void testValidateIdentityNoAudience() throws Exception {
        // audience is not configured - the request must be rejected (not NPE) even
        // when a valid token is presented
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_ALLOWED_ORG_IDS, "o-qwsedrftg3");
        AWSWebIdentityTokenAttestationValidator validator = newValidator(null);
        final String token = generateToken(AWS_ISSUER, AUDIENCE,
                "arn:aws:iam::123456789012:role/athenz.api", stsClaim("123456789012", "o-qwsedrftg3"));
        AWSAttestationData info = new AWSAttestationData();
        info.setIdentityToken(token);
        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(validator.validateIdentity(confirmation(), info, "123456789012", errMsg));
        assertTrue(errMsg.toString().contains("audience is not configured"));
    }

    @Test
    public void testValidateIdentityNoToken() {
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_AUDIENCE, AUDIENCE);
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_ALLOWED_ORG_IDS, "o-qwsedrftg3");
        AWSWebIdentityTokenAttestationValidator validator = newValidator(null);
        AWSAttestationData info = new AWSAttestationData();
        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(validator.validateIdentity(confirmation(), info, "1234", errMsg));
        assertTrue(errMsg.toString().contains("no identity token provided"));
    }

    @Test
    public void testValidateIdentityNoIssuer() throws Exception {
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_AUDIENCE, AUDIENCE);
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_ALLOWED_ORG_IDS, "o-qwsedrftg3");
        AWSWebIdentityTokenAttestationValidator validator = newValidator(null);
        // token without an issuer
        final String token = generateToken(null, AUDIENCE, "sub", stsClaim("1234", "o-qwsedrftg3"));
        AWSAttestationData info = new AWSAttestationData();
        info.setIdentityToken(token);
        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(validator.validateIdentity(confirmation(), info, "1234", errMsg));
        assertTrue(errMsg.toString().contains("no issuer present"));
    }

    @Test
    public void testValidateIdentityInvalidTokenParse() {
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_AUDIENCE, AUDIENCE);
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_ALLOWED_ORG_IDS, "o-qwsedrftg3");
        AWSWebIdentityTokenAttestationValidator validator = newValidator(null);
        AWSAttestationData info = new AWSAttestationData();
        info.setIdentityToken("not-a-jwt");
        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(validator.validateIdentity(confirmation(), info, "1234", errMsg));
    }

    @Test
    public void testValidateIdentityIssuerRegexMismatch() throws Exception {
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_AUDIENCE, AUDIENCE);
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_ALLOWED_ORG_IDS, "o-qwsedrftg3");
        AWSWebIdentityTokenAttestationValidator validator = newValidator(null);
        final String token = generateToken("https://evil.example.com", AUDIENCE, "sub",
                stsClaim("1234", "o-qwsedrftg3"));
        AWSAttestationData info = new AWSAttestationData();
        info.setIdentityToken(token);
        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(validator.validateIdentity(confirmation(), info, "1234", errMsg));
        assertTrue(errMsg.toString().contains("not a valid AWS STS issuer"));
    }

    @Test
    public void testValidateIdentityBadSignature() throws Exception {
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_AUDIENCE, AUDIENCE);
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_ALLOWED_ORG_IDS, "o-qwsedrftg3");
        // resolver points at an empty jwks so the signature cannot be verified
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks_empty.json")).toString();
        AWSWebIdentityTokenAttestationValidator validator = new AWSWebIdentityTokenAttestationValidator() {
            @Override
            JwtsSigningKeyResolver getSigningKeyResolverForIssuer(String issuer, StringBuilder errMsg) {
                return new JwtsSigningKeyResolver(jwksUri, null, true);
            }
        };
        validator.initialize(null, null);
        final String token = generateToken(AWS_ISSUER, AUDIENCE, "sub", stsClaim("1234", "o-qwsedrftg3"));
        AWSAttestationData info = new AWSAttestationData();
        info.setIdentityToken(token);
        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(validator.validateIdentity(confirmation(), info, "1234", errMsg));
        assertTrue(errMsg.toString().contains("unable to parse and validate token"));
    }

    @Test
    public void testValidateIdentityNullResolver() throws Exception {
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_AUDIENCE, AUDIENCE);
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_ALLOWED_ORG_IDS, "o-qwsedrftg3");
        AWSWebIdentityTokenAttestationValidator validator = new AWSWebIdentityTokenAttestationValidator() {
            @Override
            JwtsSigningKeyResolver getSigningKeyResolverForIssuer(String issuer, StringBuilder errMsg) {
                errMsg.append("no resolver");
                return null;
            }
        };
        validator.initialize(null, null);
        final String token = generateToken(AWS_ISSUER, AUDIENCE, "sub", stsClaim("1234", "o-qwsedrftg3"));
        AWSAttestationData info = new AWSAttestationData();
        info.setIdentityToken(token);
        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(validator.validateIdentity(confirmation(), info, "1234", errMsg));
    }

    @Test
    public void testGetSigningKeyResolverForIssuer() throws Exception {
        AWSWebIdentityTokenAttestationValidator validator = new AWSWebIdentityTokenAttestationValidator();
        validator.initialize(null, null);

        // a valid openid configuration that points at the local jwks
        File issuerDir = new File("./src/test/resources/config-openid-aws-sts/");
        File configFile = new File("./src/test/resources/config-openid-aws-sts/.well-known/openid-configuration");
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        createOpenIdConfigFile(configFile, jwksUri);
        final String issuer = "file://" + issuerDir.getCanonicalPath();

        StringBuilder errMsg = new StringBuilder(256);
        JwtsSigningKeyResolver resolver = validator.getSigningKeyResolverForIssuer(issuer, errMsg);
        org.testng.Assert.assertNotNull(resolver);
        // second call must return the cached instance
        org.testng.Assert.assertSame(validator.getSigningKeyResolverForIssuer(issuer, errMsg), resolver);
        java.nio.file.Files.delete(configFile.toPath());

        // an openid configuration without a jwks uri yields a null resolver
        File missingDir = new File("./src/test/resources/config-openid-aws-sts-missing/");
        File missingConfig = new File("./src/test/resources/config-openid-aws-sts-missing/.well-known/openid-configuration");
        createOpenIdConfigFile(missingConfig, null);
        final String missingIssuer = "file://" + missingDir.getCanonicalPath();
        StringBuilder errMsg2 = new StringBuilder(256);
        org.testng.Assert.assertNull(validator.getSigningKeyResolverForIssuer(missingIssuer, errMsg2));
        assertTrue(errMsg2.toString().contains("valid jwks uri"));
        java.nio.file.Files.delete(missingConfig.toPath());
    }

    private void createOpenIdConfigFile(File configFile, final String jwksUri) throws java.io.IOException {
        final String fileContents = jwksUri == null ? "{}" : "{\n    \"jwks_uri\": \"" + jwksUri + "\"\n}";
        java.nio.file.Files.createDirectories(configFile.toPath().getParent());
        java.nio.file.Files.write(configFile.toPath(), fileContents.getBytes());
    }

    @Test
    public void testValidateIdentityAudienceMismatch() throws Exception {
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_AUDIENCE, AUDIENCE);
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_ALLOWED_ORG_IDS, "o-qwsedrftg3");
        AWSWebIdentityTokenAttestationValidator validator = newValidator(null);
        final String token = generateToken(AWS_ISSUER, "some-other-audience", "sub",
                stsClaim("1234", "o-qwsedrftg3"));
        AWSAttestationData info = new AWSAttestationData();
        info.setIdentityToken(token);
        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(validator.validateIdentity(confirmation(), info, "1234", errMsg));
        assertTrue(errMsg.toString().contains("token audience is not the expected audience"));
    }

    @Test
    public void testValidateIdentityMissingStsClaim() throws Exception {
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_AUDIENCE, AUDIENCE);
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_ALLOWED_ORG_IDS, "o-qwsedrftg3");
        AWSWebIdentityTokenAttestationValidator validator = newValidator(null);
        final String token = generateToken(AWS_ISSUER, AUDIENCE, "sub", null);
        AWSAttestationData info = new AWSAttestationData();
        info.setIdentityToken(token);
        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(validator.validateIdentity(confirmation(), info, "1234", errMsg));
        assertTrue(errMsg.toString().contains("does not contain the expected"));
    }

    @Test
    public void testValidateIdentitySameAccountSuccess() throws Exception {
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_AUDIENCE, AUDIENCE);
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_ALLOWED_ORG_IDS, "o-qwsedrftg3");
        AWSWebIdentityTokenAttestationValidator validator = newValidator(null);
        final String token = generateToken(AWS_ISSUER, AUDIENCE,
                "arn:aws:iam::123456789012:role/athenz.api", stsClaim("123456789012", "o-qwsedrftg3"));
        AWSAttestationData info = new AWSAttestationData();
        info.setIdentityToken(token);
        StringBuilder errMsg = new StringBuilder(256);
        assertTrue(validator.validateIdentity(confirmation(), info, "123456789012", errMsg));
    }

    @Test
    public void testValidateIdentityMultipleDomainAccountsSecondMatches() throws Exception {
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_AUDIENCE, AUDIENCE);
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_ALLOWED_ORG_IDS, "o-qwsedrftg3");
        AWSWebIdentityTokenAttestationValidator validator = newValidator(null);
        final String token = generateToken(AWS_ISSUER, AUDIENCE,
                "arn:aws:iam::223456789012:role/athenz.api", stsClaim("223456789012", "o-qwsedrftg3"));
        AWSAttestationData info = new AWSAttestationData();
        info.setIdentityToken(token);
        StringBuilder errMsg = new StringBuilder(256);
        // domain is associated with two accounts - the token's account is the second one
        assertTrue(validator.validateIdentity(confirmation(), info, "123456789012,223456789012", errMsg));
    }

    @Test
    public void testValidateIdentityMissingAwsAccountClaim() throws Exception {
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_AUDIENCE, AUDIENCE);
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_ALLOWED_ORG_IDS, "o-qwsedrftg3");
        AWSWebIdentityTokenAttestationValidator validator = newValidator(null);
        Map<String, Object> claim = new HashMap<>();
        claim.put(AWSWebIdentityTokenAttestationValidator.STS_CLAIM_ORG_ID, "o-qwsedrftg3");
        final String token = generateToken(AWS_ISSUER, AUDIENCE, "sub", claim);
        AWSAttestationData info = new AWSAttestationData();
        info.setIdentityToken(token);
        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(validator.validateIdentity(confirmation(), info, "1234", errMsg));
        assertTrue(errMsg.toString().contains("required aws_account claim"));
    }

    @Test
    public void testValidateIdentityCrossAccountAuthorized() throws Exception {
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_AUDIENCE, AUDIENCE);
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_ALLOWED_ORG_IDS, "o-qwsedrftg3");
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Mockito.when(authorizer.access(eq("launch"), eq("athenz:api:123456789012"), any(Principal.class), any()))
                .thenReturn(true);
        AWSWebIdentityTokenAttestationValidator validator = newValidator(authorizer);
        final String token = generateToken(AWS_ISSUER, AUDIENCE, "arn:aws:iam::123456789012:role/athenz.api",
                stsClaim("123456789012", "o-qwsedrftg3"));
        AWSAttestationData info = new AWSAttestationData();
        info.setIdentityToken(token);
        StringBuilder errMsg = new StringBuilder(256);
        // domain account is 1234 but token account is 123456789012 - allowed via launch policy
        assertTrue(validator.validateIdentity(confirmation(), info, "1234", errMsg));
    }

    @Test
    public void testValidateIdentityCrossAccountDenied() throws Exception {
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_AUDIENCE, AUDIENCE);
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_ALLOWED_ORG_IDS, "o-qwsedrftg3");
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Mockito.when(authorizer.access(any(), any(), any(Principal.class), any())).thenReturn(false);
        AWSWebIdentityTokenAttestationValidator validator = newValidator(authorizer);
        final String token = generateToken(AWS_ISSUER, AUDIENCE, "sub", stsClaim("123456789012", "o-qwsedrftg3"));
        AWSAttestationData info = new AWSAttestationData();
        info.setIdentityToken(token);
        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(validator.validateIdentity(confirmation(), info, "1234", errMsg));
        assertTrue(errMsg.toString().contains("launch authorization check failed"));
    }

    @Test
    public void testValidateIdentityCrossAccountNoAuthorizer() throws Exception {
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_AUDIENCE, AUDIENCE);
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_ALLOWED_ORG_IDS, "o-qwsedrftg3");
        AWSWebIdentityTokenAttestationValidator validator = newValidator(null);
        final String token = generateToken(AWS_ISSUER, AUDIENCE, "sub", stsClaim("123456789012", "o-qwsedrftg3"));
        AWSAttestationData info = new AWSAttestationData();
        info.setIdentityToken(token);
        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(validator.validateIdentity(confirmation(), info, "1234", errMsg));
        assertTrue(errMsg.toString().contains("authorizer not available"));
    }

    @Test
    public void testValidateIdentityOrgIdNotAllowed() throws Exception {
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_AUDIENCE, AUDIENCE);
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_ALLOWED_ORG_IDS, "o-allowed");
        AWSWebIdentityTokenAttestationValidator validator = newValidator(null);
        final String token = generateToken(AWS_ISSUER, AUDIENCE, "sub", stsClaim("1234", "o-notallowed"));
        AWSAttestationData info = new AWSAttestationData();
        info.setIdentityToken(token);
        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(validator.validateIdentity(confirmation(), info, "1234", errMsg));
        assertTrue(errMsg.toString().contains("org_id is not in the allowed list"));
    }

    @Test
    public void testValidateIdentityOrgIdMissing() throws Exception {
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_AUDIENCE, AUDIENCE);
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_ALLOWED_ORG_IDS, "o-allowed");
        AWSWebIdentityTokenAttestationValidator validator = newValidator(null);
        Map<String, Object> claim = new HashMap<>();
        claim.put(AWSWebIdentityTokenAttestationValidator.STS_CLAIM_AWS_ACCOUNT, "1234");
        final String token = generateToken(AWS_ISSUER, AUDIENCE, "sub", claim);
        AWSAttestationData info = new AWSAttestationData();
        info.setIdentityToken(token);
        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(validator.validateIdentity(confirmation(), info, "1234", errMsg));
        assertTrue(errMsg.toString().contains("required org_id claim"));
    }

    @Test
    public void testValidateIdentityOrgIdAllowlistNotConfigured() throws Exception {
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_AUDIENCE, AUDIENCE);
        // no allowed org ids configured -> all tokens rejected
        AWSWebIdentityTokenAttestationValidator validator = newValidator(null);
        final String token = generateToken(AWS_ISSUER, AUDIENCE, "sub", stsClaim("1234", "o-qwsedrftg3"));
        AWSAttestationData info = new AWSAttestationData();
        info.setIdentityToken(token);
        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(validator.validateIdentity(confirmation(), info, "1234", errMsg));
        assertTrue(errMsg.toString().contains("no allowed org ids configured"));
    }

    @Test
    public void testValidateIdentityPrincipalValidatorAllow() throws Exception {
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_AUDIENCE, AUDIENCE);
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_ALLOWED_ORG_IDS, "o-qwsedrftg3");
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_PRINCIPAL_VALIDATOR_FACTORY_CLASS,
                "com.yahoo.athenz.instance.provider.impl.MockAttrValidatorFactory");
        AWSWebIdentityTokenAttestationValidator validator = newValidator(null);
        Map<String, Object> claim = stsClaim("1234", "o-qwsedrftg3");
        Map<String, Object> tags = new HashMap<>();
        tags.put("ASV", "ASVWORKLOADIDENTITYPLATFORM");
        claim.put(AWSWebIdentityTokenAttestationValidator.STS_CLAIM_PRINCIPAL_TAGS, tags);
        final String token = generateToken(AWS_ISSUER, AUDIENCE, "arn:aws:iam::1234:role/athenz.api", claim);
        AWSAttestationData info = new AWSAttestationData();
        info.setIdentityToken(token);
        StringBuilder errMsg = new StringBuilder(256);
        assertTrue(validator.validateIdentity(confirmation(), info, "1234", errMsg));
    }

    @Test
    public void testValidateIdentityPrincipalValidatorDeny() throws Exception {
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_AUDIENCE, AUDIENCE);
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_ALLOWED_ORG_IDS, "o-qwsedrftg3");
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_PRINCIPAL_VALIDATOR_FACTORY_CLASS,
                "com.yahoo.athenz.instance.provider.impl.MockFailingAttrValidatorFactory");
        AWSWebIdentityTokenAttestationValidator validator = newValidator(null);
        final String token = generateToken(AWS_ISSUER, AUDIENCE, "arn:aws:iam::1234:role/athenz.api",
                stsClaim("1234", "o-qwsedrftg3"));
        AWSAttestationData info = new AWSAttestationData();
        info.setIdentityToken(token);
        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(validator.validateIdentity(confirmation(), info, "1234", errMsg));
        assertTrue(errMsg.toString().contains("principal validation failed"));
    }

    @Test
    public void testValidateIdentityRoleMismatch() throws Exception {
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_AUDIENCE, AUDIENCE);
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_ALLOWED_ORG_IDS, "o-qwsedrftg3");
        AWSWebIdentityTokenAttestationValidator validator = newValidator(null);
        // the token was obtained by the sys.auth.cron role but the request is for the
        // athenz.api service - the mandatory binding must reject this
        final String token = generateToken(AWS_ISSUER, AUDIENCE,
                "arn:aws:iam::123456789012:role/sys.auth.cron", stsClaim("123456789012", "o-qwsedrftg3"));
        AWSAttestationData info = new AWSAttestationData();
        info.setIdentityToken(token);
        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(validator.validateIdentity(confirmation(), info, "123456789012", errMsg));
        assertTrue(errMsg.toString().contains("does not match requested service"));
    }

    @Test
    public void testValidateIdentityRoleFromArnPath() throws Exception {
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_AUDIENCE, AUDIENCE);
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_ALLOWED_ORG_IDS, "o-qwsedrftg3");
        AWSWebIdentityTokenAttestationValidator validator = newValidator(null);
        // the iam path must be stripped and only the final role name compared
        final String token = generateToken(AWS_ISSUER, AUDIENCE,
                "arn:aws:iam::123456789012:role/team/prod/athenz.api", stsClaim("123456789012", "o-qwsedrftg3"));
        AWSAttestationData info = new AWSAttestationData();
        info.setIdentityToken(token);
        StringBuilder errMsg = new StringBuilder(256);
        assertTrue(validator.validateIdentity(confirmation(), info, "123456789012", errMsg));
    }

    @Test
    public void testValidateIdentityRoleShortName() throws Exception {
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_AUDIENCE, AUDIENCE);
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_ALLOWED_ORG_IDS, "o-qwsedrftg3");
        AWSWebIdentityTokenAttestationValidator validator = newValidator(null);
        // the omitDomain form where the iam role is named for the service only
        final String token = generateToken(AWS_ISSUER, AUDIENCE,
                "arn:aws:iam::123456789012:role/api", stsClaim("123456789012", "o-qwsedrftg3"));
        AWSAttestationData info = new AWSAttestationData();
        info.setIdentityToken(token);
        StringBuilder errMsg = new StringBuilder(256);
        assertTrue(validator.validateIdentity(confirmation(), info, "123456789012", errMsg));
    }

    @Test
    public void testValidateIdentityInvalidSubjectArn() throws Exception {
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_AUDIENCE, AUDIENCE);
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_ALLOWED_ORG_IDS, "o-qwsedrftg3");
        AWSWebIdentityTokenAttestationValidator validator = newValidator(null);
        final String token = generateToken(AWS_ISSUER, AUDIENCE, "not-an-arn",
                stsClaim("123456789012", "o-qwsedrftg3"));
        AWSAttestationData info = new AWSAttestationData();
        info.setIdentityToken(token);
        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(validator.validateIdentity(confirmation(), info, "123456789012", errMsg));
        assertTrue(errMsg.toString().contains("unable to extract iam role"));
    }

    @Test
    public void testValidateIdentityNoSubject() throws Exception {
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_AUDIENCE, AUDIENCE);
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_ALLOWED_ORG_IDS, "o-qwsedrftg3");
        AWSWebIdentityTokenAttestationValidator validator = newValidator(null);
        // a token that passes all prior checks but carries no subject at all
        final String token = generateToken(AWS_ISSUER, AUDIENCE, null,
                stsClaim("123456789012", "o-qwsedrftg3"));
        AWSAttestationData info = new AWSAttestationData();
        info.setIdentityToken(token);
        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(validator.validateIdentity(confirmation(), info, "123456789012", errMsg));
        assertTrue(errMsg.toString().contains("unable to extract iam role"));
    }

    @Test
    public void testValidateIdentityEmptyRolePart() throws Exception {
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_AUDIENCE, AUDIENCE);
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_ALLOWED_ORG_IDS, "o-qwsedrftg3");
        AWSWebIdentityTokenAttestationValidator validator = newValidator(null);
        // an arn whose role portion is empty
        final String token = generateToken(AWS_ISSUER, AUDIENCE, "arn:aws:iam::123456789012:role/",
                stsClaim("123456789012", "o-qwsedrftg3"));
        AWSAttestationData info = new AWSAttestationData();
        info.setIdentityToken(token);
        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(validator.validateIdentity(confirmation(), info, "123456789012", errMsg));
        assertTrue(errMsg.toString().contains("unable to extract iam role"));
    }

    @Test
    public void testValidateIdentityRoleMismatchButPrincipalAllows() throws Exception {
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_AUDIENCE, AUDIENCE);
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_ALLOWED_ORG_IDS, "o-qwsedrftg3");
        // an adopter validator is the escape hatch - when the default role binding does
        // not match, the configured AttrValidator gets the final say and may allow it
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_PRINCIPAL_VALIDATOR_FACTORY_CLASS,
                "com.yahoo.athenz.instance.provider.impl.MockAttrValidatorFactory");
        AWSWebIdentityTokenAttestationValidator validator = newValidator(null);
        final String token = generateToken(AWS_ISSUER, AUDIENCE,
                "arn:aws:iam::123456789012:role/some-other-role", stsClaim("123456789012", "o-qwsedrftg3"));
        AWSAttestationData info = new AWSAttestationData();
        info.setIdentityToken(token);
        StringBuilder errMsg = new StringBuilder(256);
        assertTrue(validator.validateIdentity(confirmation(), info, "123456789012", errMsg));
    }

    @Test
    public void testValidateIdentityRoleMismatchPrincipalDenies() throws Exception {
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_AUDIENCE, AUDIENCE);
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_ALLOWED_ORG_IDS, "o-qwsedrftg3");
        // the default role binding does not match and the configured AttrValidator also
        // rejects - the request must be denied with the principal validation message
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_PRINCIPAL_VALIDATOR_FACTORY_CLASS,
                "com.yahoo.athenz.instance.provider.impl.MockFailingAttrValidatorFactory");
        AWSWebIdentityTokenAttestationValidator validator = newValidator(null);
        final String token = generateToken(AWS_ISSUER, AUDIENCE,
                "arn:aws:iam::123456789012:role/some-other-role", stsClaim("123456789012", "o-qwsedrftg3"));
        AWSAttestationData info = new AWSAttestationData();
        info.setIdentityToken(token);
        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(validator.validateIdentity(confirmation(), info, "123456789012", errMsg));
        assertTrue(errMsg.toString().contains("principal validation failed"));
    }

    @Test
    public void testNewPrincipalValidatorInvalidClass() {
        System.setProperty(AWSWebIdentityTokenAttestationValidator.AWS_PROP_WEB_IDENTITY_PRINCIPAL_VALIDATOR_FACTORY_CLASS,
                "com.yahoo.athenz.instance.provider.impl.UnknownFactoryClass");
        AWSWebIdentityTokenAttestationValidator validator = new AWSWebIdentityTokenAttestationValidator();
        try {
            validator.initialize(null, null);
            org.testng.Assert.fail();
        } catch (IllegalArgumentException ex) {
            assertTrue(ex.getMessage().contains("Invalid AWS web identity principal AttrValidatorFactory class"));
        }
    }
}
