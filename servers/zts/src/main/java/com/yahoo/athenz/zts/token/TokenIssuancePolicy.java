/*
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.zts.token;

import com.yahoo.athenz.auth.AuthorityConsts;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.ServerPrivateKey;
import com.yahoo.athenz.auth.TokenExchangeIdentityProvider;
import com.yahoo.athenz.auth.token.AccessToken;
import com.yahoo.athenz.auth.token.DPoPProof;
import com.yahoo.athenz.auth.token.IdToken;
import com.yahoo.athenz.auth.token.OAuth2Token;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.auth.util.AthenzUtils;
import com.yahoo.athenz.common.config.AuthzDetailsEntity;
import com.yahoo.athenz.common.config.AuthzDetailsEntityList;
import com.yahoo.athenz.common.server.spiffe.SpiffeUriManager;
import com.yahoo.athenz.common.server.util.ResourceUtils;
import com.yahoo.athenz.zms.RoleMeta;
import com.yahoo.athenz.zts.ResourceContext;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.cache.DataCache;
import com.yahoo.athenz.zts.utils.ZTSUtils;
import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Validator;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Token issuance rules shared by the ZTS OAuth2 token flows. All methods are
 * stateless: server configuration and the error factory are passed in by the
 * caller, so the same rules apply to every code path that issues tokens.
 */
public final class TokenIssuancePolicy {

    private static final Logger LOGGER = LoggerFactory.getLogger(TokenIssuancePolicy.class);

    public static final String OAUTH_BEARER_TOKEN = "Bearer";
    public static final String OAUTH_DPOP_TOKEN = DPoPProof.TOKEN_TYPE;
    public static final String ACCESS_LOG_ADDL_QUERY = "com.yahoo.athenz.uri.addl_query";
    public static final int JAG_ACCESS_LOG_VALUE_MAX_LENGTH = 256;
    public static final String JAG_ACCESS_LOG_TRUNCATED_MARKER = "...%5Btruncated%5D";

    private static final String KEY_TYPE = "type";

    private TokenIssuancePolicy() {
    }

    /**
     * Validate the value against the given schema type.
     * @param validator schema validator
     * @param val value to validate
     * @param type schema type name
     * @param principalDomain principal domain name
     * @param caller api name
     * @param errors error factory
     */
    public static void validate(final Validator validator, Object val, final String type,
            final String principalDomain, final String caller, final TokenIssuanceErrors errors) {

        if (val == null) {
            throw errors.requestError(caller + ": Missing or malformed " + type, caller,
                    ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }

        boolean valid;
        String error;
        try {
            Validator.Result result = validator.validate(val, type);
            valid = result.valid;
            error = result.error;
        } catch (Throwable ex) {
            valid = false;
            error = ex.getMessage();
        }

        if (!valid) {
            throw errors.requestError(ZTSUtils.validationErrorMessage(caller, val, type, error), caller,
                    ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }
    }

    /**
     * @return the configured minimum token expiry (in minutes) for the given roles or domain, 0 if none
     */
    public static int getConfiguredTokenExpiryTimeMins(DataCache data, Set<String> roles) {

        // first we're going to determine the min allowed expiry
        // time for the given set of roles

        int maxAllowedExpiry = 0;
        for (String role : roles) {
            RoleMeta rm = data.getRoleMeta(role);
            if (rm == null) {
                continue;
            }
            Integer tokenExpiryMins = rm.getTokenExpiryMins();
            if (tokenExpiryMins == null) {
                continue;
            }
            if (tokenExpiryMins > 0 && (maxAllowedExpiry == 0 || tokenExpiryMins < maxAllowedExpiry)) {
                maxAllowedExpiry = tokenExpiryMins;
            }
        }

        // if we have no role specific settings then we're going
        // to check the domain level setting

        if (maxAllowedExpiry == 0) {
            Integer tokenExpiryMins = data.getDomainData().getTokenExpiryMins();
            if (tokenExpiryMins != null && tokenExpiryMins > 0) {
                maxAllowedExpiry = tokenExpiryMins;
            }
        }

        return maxAllowedExpiry;
    }

    /**
     * @return the token timeout in seconds based on the request and the server, domain and role limits
     */
    public static int determineTokenTimeout(DataCache data, Set<String> roles, Integer minExpiryTime,
            Integer maxExpiryTime, int roleTokenDefaultTimeout, int roleTokenMaxTimeout) {

        // we're going to default our return value to the default token
        // timeout configured in the server

        int tokenTimeout = roleTokenDefaultTimeout;

        if (maxExpiryTime != null && maxExpiryTime > 0) {

            // if our max expiry time is given and it's a positive number then
            // we return that value as our result. We're checking and using the
            // max value first since that allows the biggest opportunity on the
            // client side to cache the token and return on subsequent requests

            tokenTimeout = maxExpiryTime;

        } else if (minExpiryTime != null && minExpiryTime > roleTokenDefaultTimeout) {

            // now we return the min value but only if it's bigger than our
            // default value (if the client is looking for a token that's smaller
            // than the default timeout, then they would have specified their
            // desired smaller value as the max timeout and the first if block
            // would have set accordingly.

            tokenTimeout = minExpiryTime;
        }

        // however, we're not going to allow the client to ask for unlimited
        // tokens so we'll max it out to the server's configured max timeout

        if (tokenTimeout > roleTokenMaxTimeout) {
            tokenTimeout = roleTokenMaxTimeout;
        }

        // now let's check if we have role/domain level limits

        int maxAllowedExpirySecs = getConfiguredTokenExpiryTimeMins(data, roles) * 60;
        if (maxAllowedExpirySecs > 0 && maxAllowedExpirySecs < tokenTimeout) {
            tokenTimeout = maxAllowedExpirySecs;
        }

        return tokenTimeout;
    }

    /**
     * @param tokenTimeout token timeout computed by determineTokenTimeout
     * @return the token exchange timeout, bounded by the subject access token expiry
     */
    public static int determineTokenExchangeTimeout(int tokenTimeout, AccessTokenRequest accessTokenRequest,
            long issueTime, final String principalDomain, final String caller, final TokenIssuanceErrors errors) {

        OAuth2Token subjectToken = accessTokenRequest.getSubjectTokenObj();
        if (!ZTSConsts.OAUTH_TOKEN_TYPE_ACCESS.equals(accessTokenRequest.getSubjectTokenType())
                && !JwtsHelper.TYPE_AT_JWT.equalsIgnoreCase(subjectToken.getTokenType())) {
            return tokenTimeout;
        }

        // the exchanged access token must not outlive the subject access token

        long subjectExpiryTime = subjectToken.getExpiryTime();
        if (subjectExpiryTime <= issueTime) {
            throw errors.requestError("Subject access token has expired", caller,
                    accessTokenRequest.getAudience(), principalDomain);
        }

        return (int) Math.min(tokenTimeout, subjectExpiryTime - issueTime);
    }

    /**
     * @return the id token timeout bounded by the configured id token max timeout
     */
    public static int determineAccessIdTokenTimeout(int tokenTimeout, int idTokenMaxTimeout) {
        return (tokenTimeout > idTokenMaxTimeout) ? idTokenMaxTimeout : tokenTimeout;
    }

    /**
     * @return the server private key for the preferred key type with fallback to the other types
     */
    public static ServerPrivateKey getServerPrivateKey(final String keyType, final ServerPrivateKey privateRSAKey,
            final ServerPrivateKey privateECKey, final ServerPrivateKey privateOrigKey) {

        // look for the preferred key type - RSA or EC.
        // if the preferred key type is not available then default
        // to the other algorithm - e.g. if the preferred is EC
        // and EC key is not available, then default to RSA.

        ServerPrivateKey serverPrivateKey;
        switch (keyType) {
            case ZTSConsts.RSA:
                serverPrivateKey = privateRSAKey;
                if (serverPrivateKey == null) {
                    serverPrivateKey = privateECKey;
                }
                break;
            case ZTSConsts.EC:
            default:
                serverPrivateKey = privateECKey;
                if (serverPrivateKey == null) {
                    serverPrivateKey = privateRSAKey;
                }
                break;
        }

        // Before returning, check again if we have a valid key
        // and if not then it indicates that both RSA and EC keys
        // are null, thus we must have the original single key
        // specified, so that's what we'll return.

        if (serverPrivateKey == null) {
            serverPrivateKey = privateOrigKey;
        }

        return serverPrivateKey;
    }

    /**
     * @return the private key to sign tokens with for the requested key type
     */
    public static ServerPrivateKey getSignPrivateKey(final String keyType, final String keyAlgoForJsonWebObjects,
            final ServerPrivateKey privateRSAKey, final ServerPrivateKey privateECKey,
            final ServerPrivateKey privateOrigKey) {

        // if the key type is not specified then we'll use
        // the default key type configured for the server

        if (StringUtil.isEmpty(keyType)) {
            return getServerPrivateKey(keyAlgoForJsonWebObjects, privateRSAKey, privateECKey, privateOrigKey);
        }

        ServerPrivateKey serverPrivateKey = null;
        switch (keyType.toUpperCase()) {
            case ZTSConsts.RSA:
                serverPrivateKey = privateRSAKey;
                break;
            case ZTSConsts.EC:
                serverPrivateKey = privateECKey;
                break;
        }

        // if the requested key type is not available then
        // we'll fall back to our default key

        if (serverPrivateKey == null) {
            serverPrivateKey = getServerPrivateKey(keyAlgoForJsonWebObjects, privateRSAKey, privateECKey,
                    privateOrigKey);
        }
        return serverPrivateKey;
    }

    /**
     * @return true if the principal is one of the configured proxy users
     */
    public static boolean isAuthorizedProxyUser(Set<String> proxyUsers, String principal) {
        if (proxyUsers == null) {
            return false;
        }
        return proxyUsers.contains(principal);
    }

    /**
     * Validate that the principal is authorized to request tokens on behalf of the proxy principal.
     */
    public static void validateProxyForPrincipalValue(final String proxyName, final String principalName,
            final String principalDomain, final String caller, final Set<String> authorizedProxyUsers,
            final Validator validator, final TokenIssuanceErrors errors) {

        if (StringUtil.isEmpty(proxyName)) {
            return;
        }

        validate(validator, proxyName, "EntityName", principalDomain, caller, errors);

        if (!isAuthorizedProxyUser(authorizedProxyUsers, principalName)) {
            LOGGER.error("Principal {} not authorized for proxy role token request", principalName);
            throw errors.forbiddenError("Principal: " + principalName + " not authorized for proxy access token request",
                    caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }
    }

    /**
     * Validate that an authorized service principal only requests tokens for its own domain.
     */
    public static void checkRoleTokenAuthorizedServiceRequest(final Principal principal,
            final String domainName, final String caller, final TokenIssuanceErrors errors) {

        final String authorizedService = principal.getAuthorizedService();

        // if not an authorized service then there is nothing to check

        if (StringUtil.isEmpty(authorizedService)) {
            return;
        }

        // the format for the authorized service is domain.service

        int idx = authorizedService.lastIndexOf('.');
        final String checkDomain = authorizedService.substring(0, idx);
        if (!domainName.equals(checkDomain)) {
            throw errors.forbiddenError("Authorized service domain " + checkDomain +
                            " does not match request domain " + domainName, caller,
                    domainName, principal.getDomain());
        }
    }

    /**
     * @return true if a role identity principal includes all the given roles
     */
    public static boolean isPrincipalRoleCertificateAccessValid(Principal principal, String domainName,
            Set<String> roles) {

        // if the principal was authenticated with a role certificate then
        // all the roles must be included in the certificate

        final List<String> princRoles = principal.getRoles();
        if (princRoles == null || princRoles.isEmpty()) {
            return true;
        }

        for (String role : roles) {
            final String roleName = domainName + AuthorityConsts.ROLE_SEP + role;
            if (!princRoles.contains(roleName)) {
                LOGGER.error("Principal Role list does not include '{}'", roleName);
                return false;
            }
        }
        return true;
    }

    /**
     * Validate the requested authorization details against the role and system configuration.
     */
    public static void validateAuthorizationDetails(final String authzDetails, final String[] requestedRoles,
            DataCache data, final String caller, final String domainName, final String principalDomain,
            int maxAuthzDetailsLength, final AuthzDetailsEntityList systemAuthzDetails,
            final TokenIssuanceErrors errors) {

        // if we have no authz details specified then there is nothing to check

        if (StringUtil.isEmpty(authzDetails)) {
            return;
        }

        // authz details must not exceed our configured limit

        if (authzDetails.length() > maxAuthzDetailsLength) {
            throw errors.requestError("Authorization Details exceeds configured length limit",
                    caller, domainName, principalDomain);
        }

        // if we have a single role defined in our request, extract the authz details
        // defined for the role

        List<AuthzDetailsEntity> roleAuthzDetails = null;
        if (requestedRoles != null && requestedRoles.length == 1) {
            roleAuthzDetails = data.getAuthzDetailsEntities(requestedRoles[0]);
        }

        // if we have no role and system authz details then we reject the request

        if (systemAuthzDetails == null && roleAuthzDetails == null) {
            throw errors.requestError("Authorization Details not valid for this request",
                    caller, domainName, principalDomain);
        }

        // convert our request data into a map and validate each item

        List<LinkedHashMap> authzDetailsList = JSON.fromString(authzDetails, List.class);
        if (authzDetailsList == null) {
            LOGGER.error("Unable to parse authz details: {}", authzDetails);
            throw errors.requestError("Invalid Authorization Details data", caller, domainName, principalDomain);
        }

        for (LinkedHashMap authzDetailsItem : authzDetailsList) {
            if (roleAuthzDetails != null && validateAuthzDetailsAgainstConfig(authzDetailsItem, roleAuthzDetails)) {
                continue;
            }
            if (systemAuthzDetails != null && validateAuthzDetailsAgainstConfig(authzDetailsItem,
                    systemAuthzDetails.getEntities())) {
                continue;
            }
            throw errors.requestError("Authorization Details configuration mismatch", caller, domainName,
                    principalDomain);
        }
    }

    /**
     * @return true if the authorization details item matches one of the configured entities
     */
    public static boolean validateAuthzDetailsAgainstConfig(LinkedHashMap authzDetailsItem,
            List<AuthzDetailsEntity> authzDetails) {

        // first let's look for the config with the same type

        final String type = (String) authzDetailsItem.get(KEY_TYPE);
        for (AuthzDetailsEntity entity : authzDetails) {

            if (!entity.getType().equals(type)) {
                continue;
            }

            // go through other top level fields and make sure those
            // are defined as fields in the config

            Set<String> fields = authzDetailsItem.keySet();
            for (String fieldName : fields) {

                // skip the type field

                if (KEY_TYPE.equals(fieldName)) {
                    continue;
                }

                if (!entity.isValidField(fieldName)) {
                    LOGGER.error("Invalid field name {} in request", fieldName);
                    return false;
                }
            }

            return true;
        }

        return false;
    }

    /**
     * Validate that the spiffe id from a subject token matches the token principal.
     */
    public static void verifySpiffeIdMatchesAthenzPrincipal(final String spiffeId, final String principalName,
            final String caller, final String domainName, final String principalDomain,
            final SpiffeUriManager spiffeUriManager, final TokenIssuanceErrors errors) {

        if (StringUtil.isEmpty(spiffeId) || StringUtil.isEmpty(principalName)) {
            return;
        }

        // if the principal itself is a spiffe uri (jwt-svid spiffe-subject) then it must match exactly
        if (principalName.startsWith(ZTSConsts.ZTS_CERT_SPIFFE_URI)) {
            if (!spiffeId.equals(principalName)) {
                throw errors.requestError("SPIFFE ID does not match authenticated principal",
                        caller, domainName, principalDomain);
            }
            return;
        }

        final String principalSpiffeDomain = AthenzUtils.extractPrincipalDomainName(principalName);
        final String principalSpiffeService = AthenzUtils.extractPrincipalServiceName(principalName);
        if (principalSpiffeDomain == null || principalSpiffeService == null) {
            throw errors.requestError("Invalid principal name for SPIFFE validation: " + principalName,
                    caller, domainName, principalDomain);
        }

        if (!spiffeUriManager.validateServiceCertUri(spiffeId, principalSpiffeDomain, principalSpiffeService, null)) {
            throw errors.requestError("SPIFFE ID does not match authenticated principal",
                    caller, domainName, principalDomain);
        }
    }

    /**
     * @return true if a user certificate principal is the subject of the given id token
     */
    public static boolean isAuthenticatedUserSubjectToken(Principal principal, String tokenAudience,
            OAuth2Token subjectToken, TokenExchangeIdentityProvider identityProvider, final String userDomain) {

        // Public clients cannot authenticate with a service certificate. This is
        // required for local agent executions where Copper Argos cannot practically
        // issue or distribute a workload X.509 certificate because the agent runs as
        // a user-controlled native application rather than as a provider-attested
        // workload. For that case, allow a user certificate to bind the request to
        // an ID token whose subject is the same Athenz user, even when the token
        // audience is the public client instead of the authenticated principal name.

        if (principal == null || principal.getX509Certificate() == null ||
                !userDomain.equals(principal.getDomain())) {
            return false;
        }
        if (StringUtil.isEmpty(tokenAudience)) {
            return false;
        }

        final String subjectIdentity = identityProvider == null ? subjectToken.getSubject() :
                identityProvider.getTokenIdentity(subjectToken);
        return principal.getFullName().equals(subjectIdentity);
    }

    /**
     * Validate that a caller specified audience is not a role or group reference.
     */
    public static void validateTokenAudienceNotRoleOrGroup(final String audience, final String principalDomain,
            final String caller, final TokenIssuanceErrors errors) {

        if (StringUtil.isEmpty(audience)) {
            return;
        }

        if (containsWhitespaceOrControlChars(audience)) {
            throw errors.requestError("Audience must not contain whitespace or control characters",
                    caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }

        if (isRoleOrGroupAudience(audience)) {
            throw errors.requestError("Audience must not be in the form of a role or group reference",
                    caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }
    }

    /**
     * @return true if the value contains any whitespace or control characters
     */
    public static boolean containsWhitespaceOrControlChars(final String value) {
        for (int i = 0; i < value.length(); i++) {
            final char ch = value.charAt(i);
            if (Character.isWhitespace(ch) || Character.isSpaceChar(ch) || Character.isISOControl(ch)) {
                return true;
            }
        }
        return false;
    }

    /**
     * @return true if the audience is in the form of a role or group reference
     */
    public static boolean isRoleOrGroupAudience(final String audience) {

        if (StringUtil.isEmpty(audience)) {
            return false;
        }

        final int firstColon = audience.indexOf(':');
        if (firstColon == -1) {
            return false;
        }

        if (!isCompoundName(audience, 0, firstColon)) {
            return false;
        }

        final int secondColon = audience.indexOf(':', firstColon + 1);
        if (secondColon == -1) {
            // domain:role-name, client-id:role-name, domain:role.name or domain:group.name
            return isCompoundName(audience, firstColon + 1, audience.length());
        }

        // client-id:domain:role.name or client-id:domain:group.name

        if (!isCompoundName(audience, firstColon + 1, secondColon)) {
            return false;
        }

        final int nameStart;
        if (audience.startsWith(AuthorityConsts.ROLE_SEP, secondColon)) {
            nameStart = secondColon + AuthorityConsts.ROLE_SEP.length();
        } else if (audience.startsWith(AuthorityConsts.GROUP_SEP, secondColon)) {
            nameStart = secondColon + AuthorityConsts.GROUP_SEP.length();
        } else {
            return false;
        }
        return isCompoundName(audience, nameStart, audience.length());
    }

    /**
     * @return true if the given range of the value is a valid compound name
     */
    public static boolean isCompoundName(final String value, int from, int to) {
        if (from >= to) {
            return false;
        }
        boolean componentStart = true;
        for (int i = from; i < to; i++) {
            final char ch = value.charAt(i);
            if (ch == '.') {
                if (componentStart) {
                    return false;
                }
                componentStart = true;
            } else if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_') {
                componentStart = false;
            } else if (ch == '-') {
                if (componentStart) {
                    return false;
                }
            } else {
                return false;
            }
        }
        return !componentStart;
    }

    /**
     * Reject requests from authorized service principals for the given action.
     */
    public static void disallowAuthorizedServicePrincipal(final String authorizedService,
            final String actionDescription, final String caller, final String principalDomain,
            final TokenIssuanceErrors errors) {
        if (!StringUtil.isEmpty(authorizedService)) {
            LOGGER.error("The authorized service principal {} cannot be used for {}",
                    authorizedService, actionDescription);
            throw errors.forbiddenError("Authorized service principal forbidden for " + actionDescription, caller,
                    ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }
    }

    /**
     * @return the error message for a principal not included in the requested roles
     */
    public static String tokenErrorMessage(final String caller, final String principalName, final String domainName,
            String[] requestedRoleList) {

        final String roleComment = requestedRoleList == null ? "any role" : "the requested role(s)";
        return caller + ": principal " + principalName + " is not included in "
                + roleComment + " in domain " + domainName;
    }

    /**
     * Log roles granted to the principal that were not part of the requested role list.
     */
    public static void logUnrequestedRoles(final String principalName, String[] requestedRoleList,
            Set<String> roles, boolean logUnrequestedRolesEnabled) {

        if (!logUnrequestedRolesEnabled || requestedRoleList == null || requestedRoleList.length == 0) {
            return;
        }

        for (String role : roles) {
            boolean requested = false;
            for (String requestedRole : requestedRoleList) {
                if (role.equalsIgnoreCase(requestedRole)) {
                    requested = true;
                    break;
                }
            }
            if (!requested) {
                LOGGER.info("principal {} was authorized for role {} which was not part of the requested role list",
                        principalName, role);
            }
        }
    }

    /**
     * @return the requested roles for a token exchange request, or null if the scope is not
     *         a subset of the subject token scope
     */
    public static String[] tokenExchangeRequestedRoles(AccessTokenRequest accessTokenRequest,
            OAuth2Token subjectToken, final String requestDomainName) {

        // first let's extract our scope claim from the subject token
        // and convert that into a set

        Object scopeClaim = subjectToken.getClaim(AccessToken.CLAIM_SCOPE_STD);
        if (scopeClaim == null) {
            LOGGER.error("subject token does not contain the scope claim");
            return null;
        }

        final String sourceDomainName = subjectToken.getAudience();
        if (StringUtil.isEmpty(sourceDomainName)) {
            LOGGER.error("subject token does not contain a valid audience");
            return null;
        }

        final String scopeClaimStr = scopeClaim.toString().trim();
        if (scopeClaimStr.isEmpty()) {
            LOGGER.error("subject token does not contain any scope roles");
            return null;
        }

        Set<String> scopeRoles = new HashSet<>(Arrays.asList(scopeClaimStr.split("\\s+")));

        final String scope = accessTokenRequest.getScope();
        if (StringUtil.isEmpty(scope)) {
            String[] requestedRoles = getSubjectTokenRolesForDomain(scopeRoles, sourceDomainName,
                    requestDomainName);
            if (requestedRoles == null || requestedRoles.length == 0) {
                LOGGER.error("subject token does not contain any roles for requested domain {}", requestDomainName);
                return null;
            }
            return requestedRoles;
        }

        // if we have scope specified then we need to make sure it includes
        // roles from the requested target domain

        AccessTokenScope tokenScope = new AccessTokenScope(scope, null);
        if (!tokenScope.getDomainNames().contains(requestDomainName)) {
            LOGGER.error("token scope domains {} do not include requested domain {}",
                    tokenScope.getDomainNames(), requestDomainName);
            return null;
        }

        // and the scope roles must be a subset of the subject token roles.
        // Simple roles belong only to the subject token audience. Roles from
        // any other domain must be fully qualified in the subject token.

        String[] requestedRoles = tokenScope.getRoleNames(requestDomainName);
        if (requestedRoles == null) {
            requestedRoles = getSubjectTokenRolesForDomain(scopeRoles, sourceDomainName,
                    requestDomainName);
            if (requestedRoles == null || requestedRoles.length == 0) {
                LOGGER.error("subject token does not contain any roles for requested domain {}", requestDomainName);
                return null;
            }
            return requestedRoles;
        } else if (subjectTokenHasRequestedRoles(scopeRoles, sourceDomainName, requestDomainName,
                requestedRoles)) {
            return requestedRoles;
        } else {
            LOGGER.error("requested roles are not a subset of subject token roles");
            return null;
        }
    }

    /**
     * @return true if all the requested roles are included in the subject token scopes
     */
    public static boolean subjectTokenHasRequestedRoles(Set<String> subjectScopes, final String sourceDomainName,
            final String requestDomainName, String[] requestedRoles) {

        final boolean isSourceDomain = requestDomainName.equals(sourceDomainName);
        for (String requestedRole : requestedRoles) {
            if (subjectScopes.contains(ResourceUtils.roleResourceName(requestDomainName, requestedRole))) {
                continue;
            }
            if (isSourceDomain && subjectScopes.contains(requestedRole)) {
                continue;
            }
            return false;
        }
        return true;
    }

    /**
     * @return the roles from the subject token scopes that belong to the requested domain
     */
    public static String[] getSubjectTokenRolesForDomain(Set<String> subjectScopes, final String sourceDomainName,
            final String requestDomainName) {

        Set<String> requestedRoles = new HashSet<>();
        final String roleScopePrefix = requestDomainName + OAuthTokenScope.OBJECT_ROLE;
        final boolean isSourceDomain = requestDomainName.equals(sourceDomainName);
        for (String subjectScope : subjectScopes) {
            if (AccessTokenScope.OBJECT_OPENID.equals(subjectScope)) {
                continue;
            }
            if (subjectScope.startsWith(roleScopePrefix)) {
                String roleName = subjectScope.substring(roleScopePrefix.length());
                if (!roleName.isEmpty()) {
                    requestedRoles.add(roleName);
                }
            } else if (!subjectScope.contains(":") && isSourceDomain) {
                requestedRoles.add(subjectScope);
            }
        }
        return requestedRoles.toArray(new String[0]);
    }

    /**
     * @return the scope response value for the given roles in a single domain
     */
    public static String generateScopeResponse(Set<String> roles, final String domainName, boolean openIdScope) {

        StringBuilder sb = new StringBuilder();
        for (String role : roles) {
            sb.append(domainName).append(OAuthTokenScope.OBJECT_ROLE).append(role).append(" ");
        }

        // either remove the trailing id or add the openid scope if requested

        if (openIdScope) {
            sb.append(AccessTokenScope.OBJECT_OPENID);
        } else {
            if (sb.length() > 0) {
                sb.setLength(sb.length() - 1); // remove last space
            }
        }
        return sb.toString();
    }

    /**
     * @return the access token scope list; audience domain roles are not qualified
     */
    public static List<String> generateAccessTokenScopeList(Map<String, Set<String>> rolesByDomain,
            final String audienceDomainName) {

        List<String> scopes = new ArrayList<>();
        for (String domainName : new TreeSet<>(rolesByDomain.keySet())) {
            final boolean isAudienceDomain = domainName.equals(audienceDomainName);
            for (String role : new TreeSet<>(rolesByDomain.get(domainName))) {
                if (isAudienceDomain) {
                    scopes.add(role);
                } else {
                    scopes.add(domainName + OAuthTokenScope.OBJECT_ROLE + role);
                }
            }
        }
        return scopes;
    }

    /**
     * @return the scope response value for the given qualified scopes
     */
    public static String generateScopeResponse(List<String> scopes, boolean openIdScope) {
        StringBuilder sb = new StringBuilder(String.join(" ", scopes));
        if (openIdScope) {
            if (sb.length() > 0) {
                sb.append(" ");
            }
            sb.append(AccessTokenScope.OBJECT_OPENID);
        }
        return sb.toString();
    }

    /**
     * @return the access token audience, optionally including the single role name
     */
    public static String getAccessTokenAudience(final String domainName, boolean roleInAudClaim, List<String> roles) {
        return (roleInAudClaim && roles != null && roles.size() == 1) ?
                domainName + ":" + roles.get(0) : domainName;
    }

    /**
     * @return the token type for the response based on the DPoP binding
     */
    public static String accessTokenType(AccessTokenRequest accessTokenRequest) {
        return accessTokenRequest.getDPoPJwkThumbprint() != null ? OAUTH_DPOP_TOKEN : OAUTH_BEARER_TOKEN;
    }

    /**
     * @return the spiffe id from a ZTS issued token or JWT-SVID subject, or null
     */
    public static String extractSpiffeIdFromToken(final OAuth2Token token) {
        if (token == null) {
            return null;
        }

        // Only ZTS-issued spiffe claims and JWT-SVID subject SPIFFE URIs are recognized.
        // Other identity-provider-specific SPIFFE claims are not propagated.
        final Object spiffeClaim = token.getClaim(IdToken.CLAIM_SPIFFE);
        if (spiffeClaim != null) {
            final String spiffeId = spiffeClaim.toString();
            if (!StringUtil.isEmpty(spiffeId) && spiffeId.startsWith(ZTSConsts.ZTS_CERT_SPIFFE_URI)) {
                return spiffeId;
            }
        }

        final String subject = token.getSubject();
        if (!StringUtil.isEmpty(subject) && subject.startsWith(ZTSConsts.ZTS_CERT_SPIFFE_URI)) {
            return subject;
        }

        return null;
    }

    /**
     * Bind the access token to the client certificate, DPoP key and proxy principals.
     */
    public static void setAccessTokenConfirmation(AccessToken accessToken, Principal principal,
            AccessTokenRequest accessTokenRequest) {

        // if we have a certificate used for mTLS authentication then
        // we're going to bind the certificate to the access token

        X509Certificate cert = principal.getX509Certificate();
        if (cert != null) {
            accessToken.setConfirmX509CertHash(cert);
        }

        // if the client presented a valid DPoP proof then we're going to
        // bind the access token to the proof key as well. we keep the
        // certificate hash so existing mTLS resource servers continue to work

        final String jkt = accessTokenRequest.getDPoPJwkThumbprint();
        if (jkt != null) {
            accessToken.setConfirmJwkThumbprint(jkt);
        }

        // include the optional proxy principals if specified

        if (accessTokenRequest.getProxyPrincipalsSpiffeUris() != null) {
            accessToken.setConfirmProxyPrincipalSpiffeUris(accessTokenRequest.getProxyPrincipalsSpiffeUris());
        }
    }

    /**
     * Record the ID-JAG request details in the access log.
     */
    public static void setJAGAccessLogData(ResourceContext ctx, AccessTokenRequest request, Principal client,
            String subjectIdentity, String issuedTokenJti) {

        // The source token has already been validated by AccessTokenRequest. Log its
        // subject even when a later authorization check fails. The resolved Athenz
        // identity and the issued token id are added only after successful issuance.

        final boolean issuingJAG = request.getRequestType() == AccessTokenRequest.RequestType.JAG_TOKEN_EXCHANGE;
        final OAuth2Token sourceToken = issuingJAG ? request.getSubjectTokenObj() : request.getJagTokenObj();
        StringBuilder query = new StringBuilder(request.getQueryLogData());
        appendAccessLogQueryParam(query, "token_operation", issuingJAG ? "id_jag_issue" : "id_jag_exchange");
        appendAccessLogQueryParam(query, "client", client == null ? null : client.getFullName());
        appendAccessLogQueryParam(query, "token_subject", sourceToken.getSubject());
        appendAccessLogQueryParam(query, "subject", subjectIdentity);
        appendAccessLogQueryParam(query, "jag_jti", issuingJAG ? issuedTokenJti : sourceToken.getJwtId());
        if (!issuingJAG) {
            appendAccessLogQueryParam(query, "access_token_jti", issuedTokenJti);
        }
        ctx.request().setAttribute(ACCESS_LOG_ADDL_QUERY, query.toString());
    }

    static void appendAccessLogQueryParam(StringBuilder query, String name, String value) {
        if (StringUtil.isEmpty(value)) {
            return;
        }
        String encodedValue = URLEncoder.encode(value, StandardCharsets.UTF_8);
        if (encodedValue.length() > JAG_ACCESS_LOG_VALUE_MAX_LENGTH) {
            // Keep the encoded value bounded without splitting a UTF-8 character or
            // a percent escape. ZTS-issued token ids are UUIDs and remain intact.
            StringBuilder prefix = new StringBuilder(JAG_ACCESS_LOG_VALUE_MAX_LENGTH);
            for (int offset = 0; offset < value.length();) {
                int codePoint = value.codePointAt(offset);
                String encodedCodePoint = URLEncoder.encode(new String(Character.toChars(codePoint)),
                        StandardCharsets.UTF_8);
                if (prefix.length() + encodedCodePoint.length() >
                        JAG_ACCESS_LOG_VALUE_MAX_LENGTH - JAG_ACCESS_LOG_TRUNCATED_MARKER.length()) {
                    break;
                }
                prefix.append(encodedCodePoint);
                offset += Character.charCount(codePoint);
            }
            encodedValue = prefix.append(JAG_ACCESS_LOG_TRUNCATED_MARKER).toString();
        }
        if (query.length() > 0) {
            query.append('&');
        }
        query.append(name).append('=').append(encodedValue);
    }
}
