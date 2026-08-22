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

import com.nimbusds.jwt.JWTClaimsSet;
import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.token.IdToken;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import com.yahoo.athenz.common.server.util.Utils;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigCsv;
import com.yahoo.athenz.instance.provider.AWSAttestationValidator;
import com.yahoo.athenz.instance.provider.AttrValidator;
import com.yahoo.athenz.instance.provider.AttrValidatorFactory;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

import static com.yahoo.athenz.common.server.util.config.ConfigManagerSingleton.CONFIG_MANAGER;
import static com.yahoo.athenz.instance.provider.InstanceProvider.ZTS_INSTANCE_ATTESTATION_DATA_SUBJECT;
import static com.yahoo.athenz.instance.provider.InstanceProvider.ZTS_INSTANCE_AWS_PRINCIPAL_TAG_PREFIX;

/**
 * AWSWebIdentityTokenAttestationValidator verifies an instance identity by
 * validating an AWS-issued OIDC web identity JWT (STS outbound identity
 * federation) provided in the attestation data.
 * <p>
 * AWS issues these tokens with a per-account issuer (e.g.
 * {@code https://<uuid>.tokens.sts.global.api.aws}), so the issuer is extracted
 * from the token, matched against a configurable pattern, and its JWKS is
 * resolved (and cached) per issuer. The token's identity attributes live in a
 * nested claim keyed {@code https://sts.amazonaws.com/}. The validator confirms:
 * <ul>
 *   <li>the token signature and expiry (against the issuer JWKS),</li>
 *   <li>the audience matches the configured audience,</li>
 *   <li>the token's aws_account matches the domain's AWS account, or a launch
 *       authorization is granted for the token's account,</li>
 *   <li>the org_id is present in the configured allowlist,</li>
 *   <li>the iam role name in the token subject matches the requested athenz
 *       service (the default binding that prevents one role from obtaining
 *       another service's identity), and</li>
 *   <li>the sub and principal_tags pass an adopter-supplied {@link AttrValidator}
 *       if one is configured. When configured, the AttrValidator has the final
 *       say on the principal and is the escape hatch for adopters whose iam role
 *       names diverge from the service - it is consulted even when the default
 *       role binding above does not match. Without one, the default binding is
 *       strictly enforced.</li>
 * </ul>
 */
public class AWSWebIdentityTokenAttestationValidator implements AWSAttestationValidator {

    private static final Logger LOGGER = LoggerFactory.getLogger(AWSWebIdentityTokenAttestationValidator.class);

    static final String AWS_PROP_WEB_IDENTITY_AUDIENCE = "athenz.zts.aws_web_identity_audience";
    static final String AWS_PROP_WEB_IDENTITY_ISSUER_REGEX    = "athenz.zts.aws_web_identity_issuer_regex";
    static final String AWS_PROP_WEB_IDENTITY_ALLOWED_ORG_IDS = "athenz.zts.aws_web_identity_allowed_org_ids";
    static final String AWS_PROP_WEB_IDENTITY_STS_CLAIM_NAME  = "athenz.zts.aws_web_identity_sts_claim_name";
    static final String AWS_PROP_WEB_IDENTITY_PRINCIPAL_VALIDATOR_FACTORY_CLASS = "athenz.zts.aws_web_identity_principal_validator_factory_class";

    static final String AWS_DEFAULT_WEB_IDENTITY_ISSUER_REGEX = "https://[a-z0-9-]+\\.tokens\\.sts\\.global\\.api\\.aws";
    static final String AWS_DEFAULT_STS_CLAIM_NAME    = "https://sts.amazonaws.com/";

    static final String STS_CLAIM_AWS_ACCOUNT   = "aws_account";
    static final String STS_CLAIM_ORG_ID        = "org_id";
    static final String STS_CLAIM_PRINCIPAL_TAGS = "principal_tags";

    static final String ACTION_LAUNCH = "launch";
    static final String AWS_PROP_WEB_IDENTITY_DISCOVERY_PROXY = "athenz.zts.aws_web_identity_discovery_proxy";

    String audience;
    String stsClaimName;
    Pattern issuerPattern;
    DynamicConfigCsv allowedOrgIds;
    Authorizer authorizer;
    AttrValidator principalValidator;

    final JwtsHelper jwtsHelper = new JwtsHelper();
    final Map<String, JwtsSigningKeyResolver> issuersMap = new ConcurrentHashMap<>();
    String oidcDiscoveryProxy;

    @Override
    public void initialize(SSLContext sslContext, Authorizer authorizer) {

        this.authorizer = authorizer;
        audience = System.getProperty(AWS_PROP_WEB_IDENTITY_AUDIENCE, null);
        issuerPattern = Pattern.compile(System.getProperty(AWS_PROP_WEB_IDENTITY_ISSUER_REGEX, AWS_DEFAULT_WEB_IDENTITY_ISSUER_REGEX));
        stsClaimName = System.getProperty(AWS_PROP_WEB_IDENTITY_STS_CLAIM_NAME, AWS_DEFAULT_STS_CLAIM_NAME);
        allowedOrgIds = new DynamicConfigCsv(CONFIG_MANAGER, AWS_PROP_WEB_IDENTITY_ALLOWED_ORG_IDS, null);
        oidcDiscoveryProxy = System.getProperty(AWS_PROP_WEB_IDENTITY_DISCOVERY_PROXY, null);
        principalValidator = newPrincipalValidator(sslContext);
        if (audience == null) {
            LOGGER.error("audience must be set for validation, no instance requests will be authorized.");
        }
        List<String> allowedOrgIdList = allowedOrgIds.getStringsList();
        if (allowedOrgIdList == null || allowedOrgIdList.isEmpty()) {
            LOGGER.error("one or more org ids must be set for validation, no instance requests will be authorized.");
        }
    }

    static AttrValidator newPrincipalValidator(final SSLContext sslContext) {
        final String factoryClass = System.getProperty(AWS_PROP_WEB_IDENTITY_PRINCIPAL_VALIDATOR_FACTORY_CLASS);
        if (StringUtil.isEmpty(factoryClass)) {
            return null;
        }
        LOGGER.info("AWS web identity principal AttrValidatorFactory class: {}", factoryClass);
        AttrValidatorFactory attrValidatorFactory;
        try {
            attrValidatorFactory = (AttrValidatorFactory) Class.forName(factoryClass).getConstructor().newInstance();
        } catch (Exception ex) {
            LOGGER.error("Invalid AWS web identity principal AttrValidatorFactory class: {}", factoryClass, ex);
            throw new IllegalArgumentException("Invalid AWS web identity principal AttrValidatorFactory class: " + factoryClass);
        }
        return attrValidatorFactory.create(sslContext);
    }

    String getIssuerFromToken(final String jwToken, StringBuilder errMsg) {
        try {
            final String tokenWithoutSig = jwToken.substring(0, jwToken.lastIndexOf('.') + 1);
            JWTClaimsSet claimsSet = JwtsHelper.parseJWTWithoutSignature(tokenWithoutSig);
            final String issuer = claimsSet.getIssuer();
            if (StringUtil.isEmpty(issuer)) {
                errMsg.append("no issuer present in the identity token");
            }
            return issuer;
        } catch (Exception ex) {
            errMsg.append("unable to parse identity token: ").append(ex.getMessage());
            return null;
        }
    }

    JwtsSigningKeyResolver getSigningKeyResolverForIssuer(final String issuer, StringBuilder errMsg) {
        JwtsSigningKeyResolver signingKeyResolver = issuersMap.get(issuer);
        if (signingKeyResolver == null) {
            final String openIdConfigUri = issuer + "/.well-known/openid-configuration";
            final String jwksUri = jwtsHelper.extractJwksUri(openIdConfigUri, null, oidcDiscoveryProxy);
            if (StringUtil.isEmpty(jwksUri)) {
                errMsg.append("identity token issuer does not have a valid jwks uri");
                return null;
            }
            signingKeyResolver = new JwtsSigningKeyResolver(jwksUri, null, oidcDiscoveryProxy, true);
            issuersMap.put(issuer, signingKeyResolver);
        }
        return signingKeyResolver;
    }

    @Override
    public boolean validateIdentity(InstanceConfirmation confirmation, AWSAttestationData info,
            final String awsAccount, StringBuilder errMsg) {

        // the audience is a mandatory configuration - so we return an error immediately
        if (audience == null) {
            errMsg.append("audience is not configured for AWS web identity attestation");
            return false;
        }

        final String jwToken = info.getIdentityToken();
        if (StringUtil.isEmpty(jwToken)) {
            errMsg.append("no identity token provided in attestation data");
            return false;
        }

        // extract the issuer from the token and verify it matches our expected
        // AWS STS issuer pattern (the issuer is unique per aws account)

        final String issuer = getIssuerFromToken(jwToken, errMsg);
        if (StringUtil.isEmpty(issuer)) {
            return false;
        }
        if (!issuerPattern.matcher(issuer).matches()) {
            errMsg.append("token issuer is not a valid AWS STS issuer: ").append(issuer);
            return false;
        }

        // resolve the issuer's signing keys and validate the token signature/expiry

        JwtsSigningKeyResolver signingKeyResolver = getSigningKeyResolverForIssuer(issuer, errMsg);
        if (signingKeyResolver == null) {
            return false;
        }

        IdToken idToken;
        try {
            idToken = new IdToken(jwToken, signingKeyResolver);
        } catch (Exception ex) {
            errMsg.append("unable to parse and validate token: ").append(ex.getMessage());
            return false;
        }

        // verify that the token audience is set for our service

        if (!audience.equals(idToken.getAudience())) {
            errMsg.append("token audience is not the expected audience: ").append(idToken.getAudience());
            return false;
        }

        // extract the nested aws sts claim which carries the identity attributes

        final Object stsClaimObject = idToken.getClaim(stsClaimName);
        if (!(stsClaimObject instanceof Map)) {
            errMsg.append("token does not contain the expected ").append(stsClaimName).append(" claim");
            return false;
        }
        @SuppressWarnings("unchecked")
        final Map<String, Object> stsClaim = (Map<String, Object>) stsClaimObject;

        // verify the aws account and org id claims

        if (!validateAwsAccount(confirmation, stsClaim, awsAccount, errMsg)) {
            return false;
        }
        if (!validateOrgId(stsClaim, errMsg)) {
            return false;
        }

        // default binding: the iam role that obtained the token (sub) must match the
        // requested athenz service - this prevents one role in the account from
        // obtaining a certificate for a different service identity. adopters whose iam
        // role names diverge from the service can configure a principal AttrValidator,
        // which is then given the final say even when this default binding does not
        // match. without such a validator the default binding is strictly enforced.

        StringBuilder roleErrMsg = new StringBuilder(256);
        if (!validateRole(confirmation, idToken, roleErrMsg) && principalValidator == null) {
            errMsg.append(roleErrMsg);
            return false;
        }

        // run the adopter specific principal validation (also the escape hatch above)

        return validatePrincipal(confirmation, idToken, stsClaim, errMsg);
    }

    boolean validateRole(final InstanceConfirmation confirmation, final IdToken idToken, StringBuilder errMsg) {

        // the token subject is the iam role arn that obtained the token; extract the
        // role name and require it to match the requested athenz service identity -
        // either the fully qualified <domain>.<service> or just the <service> name
        // (mirroring the role name accepted by the sts credentials path)

        final String roleName = getRoleNameFromArn(idToken.getSubject());
        if (StringUtil.isEmpty(roleName)) {
            errMsg.append("unable to extract iam role name from token subject: ").append(idToken.getSubject());
            return false;
        }
        final String serviceName = confirmation.getService();
        final String expectedRole = confirmation.getDomain() + "." + serviceName;
        if (roleName.equals(expectedRole) || roleName.equals(serviceName)) {
            return true;
        }
        errMsg.append("token principal role ").append(roleName)
                .append(" does not match requested service ").append(expectedRole);
        return false;
    }

    static String getRoleNameFromArn(final String sub) {

        // expected arn format: arn:aws:iam::<account>:role/<optional/path/>/<name>
        // the role name is the final path segment (the iam path, if any, is stripped)

        if (StringUtil.isEmpty(sub)) {
            return null;
        }
        final int idx = sub.indexOf(":role/");
        if (idx < 0) {
            return null;
        }
        final String rolePart = sub.substring(idx + ":role/".length());
        if (rolePart.isEmpty()) {
            return null;
        }
        final int slash = rolePart.lastIndexOf('/');
        return slash < 0 ? rolePart : rolePart.substring(slash + 1);
    }

    boolean validateAwsAccount(final InstanceConfirmation confirmation, final Map<String, Object> stsClaim,
            final String awsAccount, StringBuilder errMsg) {

        final String tokenAwsAccount = getStringValue(stsClaim.get(STS_CLAIM_AWS_ACCOUNT));
        if (StringUtil.isEmpty(tokenAwsAccount)) {
            errMsg.append("token does not contain the required aws_account claim");
            return false;
        }

        // if the token account matches one of the domain's (possibly
        // comma-separated) accounts we're done

        if (Utils.parseAwsAccounts(awsAccount).contains(tokenAwsAccount)) {
            return true;
        }

        // otherwise the request may still be authorized via an rbac launch policy
        // that grants the domain/service the ability to launch in the token's account

        if (authorizer == null) {
            errMsg.append("authorizer not available for cross-account launch authorization");
            return false;
        }

        final String domainName = confirmation.getDomain();
        final String serviceName = confirmation.getService();
        final String resource = String.format("%s:%s:%s", domainName, serviceName, tokenAwsAccount);
        Principal principal = SimplePrincipal.create(domainName, serviceName, (String) null);
        if (!authorizer.access(ACTION_LAUNCH, resource, principal, null)) {
            errMsg.append("aws account mismatch and launch authorization check failed for resource: ").append(resource);
            return false;
        }
        return true;
    }

    boolean validateOrgId(final Map<String, Object> stsClaim, StringBuilder errMsg) {

        // org id validation is mandatory - the allowlist must be configured and
        // the token's org id must be present in it

        List<String> allowedOrgIdList = allowedOrgIds.getStringsList();
        if (allowedOrgIdList == null || allowedOrgIdList.isEmpty()) {
            errMsg.append("no allowed org ids configured - rejecting all web identity tokens");
            return false;
        }
        final String tokenOrgId = getStringValue(stsClaim.get(STS_CLAIM_ORG_ID));
        if (StringUtil.isEmpty(tokenOrgId)) {
            errMsg.append("token does not contain the required org_id claim");
            return false;
        }
        if (!allowedOrgIdList.contains(tokenOrgId)) {
            errMsg.append("token org_id is not in the allowed list: ").append(tokenOrgId);
            return false;
        }
        return true;
    }

    boolean validatePrincipal(final InstanceConfirmation confirmation, final IdToken idToken,
            final Map<String, Object> stsClaim, StringBuilder errMsg) {

        // adopter specific validation of the sub and principal_tags claims is
        // optional - if no validator is configured we skip the check

        if (principalValidator == null) {
            return true;
        }

        final Map<String, String> attributes = confirmation.getAttributes();
        if (attributes != null) {
            attributes.put(ZTS_INSTANCE_ATTESTATION_DATA_SUBJECT, idToken.getSubject());
            final Object tagsObject = stsClaim.get(STS_CLAIM_PRINCIPAL_TAGS);
            if (tagsObject instanceof Map) {
                @SuppressWarnings("unchecked")
                final Map<String, Object> principalTags = (Map<String, Object>) tagsObject;
                for (Map.Entry<String, Object> entry : principalTags.entrySet()) {
                    attributes.put(ZTS_INSTANCE_AWS_PRINCIPAL_TAG_PREFIX + entry.getKey(), getStringValue(entry.getValue()));
                }
            }
        }

        if (!principalValidator.confirm(confirmation)) {
            errMsg.append("principal validation failed for subject: ").append(idToken.getSubject());
            return false;
        }
        return true;
    }

    static String getStringValue(final Object value) {
        return value == null ? null : value.toString();
    }
}
