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

package com.yahoo.athenz.zts.pdp;

import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.token.OAuth2Token;
import com.yahoo.athenz.common.server.pdp.authzen.Action;
import com.yahoo.athenz.common.server.pdp.authzen.Resource;
import com.yahoo.athenz.common.server.pdp.authzen.Subject;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeSet;

/**
 * Maps Athenz request data onto the AuthZEN-aligned model using the
 * Athenz vocabulary defined in the external PDP design document.
 */
public final class AuthZenRequestBuilder {

    public static final String ACTION_ISSUE_TOKEN = "issue_token";
    public static final String ACTION_ASSUME_ROLE = "assume_role";

    public static final String RESOURCE_TOKEN = "athenz_token";
    public static final String RESOURCE_ROLE = "athenz_role";
    public static final String RESOURCE_ATHENZ = "athenz_resource";

    public static final String SUBJECT_USER = "user";
    public static final String SUBJECT_SERVICE = "service";

    public static final String TOKEN_TYPE_ACCESS = "access_token";

    public static final String CTX_REQUEST_ID = "request_id";
    public static final String CTX_TIME = "time";
    public static final String CTX_GRANT_TYPE = "grant_type";
    public static final String CTX_REQUEST_TYPE = "request_type";
    public static final String CTX_EXCHANGE_TYPE = "exchange_type";
    public static final String CTX_CLIENT_IP = "client_ip";
    public static final String CTX_AUDIENCE = "audience";
    public static final String CTX_REQUESTED_SCOPE = "requested_scope";
    public static final String CTX_REQUESTED_EXPIRES_IN = "requested_expires_in";
    public static final String CTX_PROXY_FOR_PRINCIPAL = "proxy_for_principal";
    public static final String CTX_ACTOR = "actor";
    public static final String CTX_CLIENT = "client";
    public static final String CTX_SUBJECT_TOKEN = "subject_token";
    public static final String CTX_ACTOR_TOKEN = "actor_token";
    public static final String CTX_DPOP_BOUND = "dpop_bound";
    public static final String CTX_MODE = "mode";

    private final String userDomain;

    /**
     * @param userDomain configured user domain name
     */
    public AuthZenRequestBuilder(final String userDomain) {
        this.userDomain = userDomain;
    }

    /**
     * @param principal authenticated principal
     * @return subject with the principal's authentication attributes
     */
    public Subject subject(final Principal principal) {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("domain", principal.getDomain());
        properties.put("name", principal.getName());
        putIfNotNull(properties, "authority", principal.getAuthority() == null ? null
                : principal.getAuthority().getID());
        putIfNotNull(properties, "issuer", principal.getIssuerIdentity());
        putIfNotNull(properties, "authorized_service", principal.getAuthorizedService());
        properties.put("role_identity", principal.getRoles() != null);
        properties.put("mtls", principal.getX509Certificate() != null);
        return new Subject(subjectType(principal.getDomain()), principal.getFullName(), properties);
    }

    /**
     * @param principalName principal name not backed by an authenticated principal
     *        (e.g. the subject of a token being exchanged)
     * @return subject with the domain and name attributes
     */
    public Subject subject(final String principalName) {
        final int idx = principalName.lastIndexOf('.');
        final String domain = idx == -1 ? "" : principalName.substring(0, idx);
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("domain", domain);
        properties.put("name", idx == -1 ? principalName : principalName.substring(idx + 1));
        return new Subject(subjectType(domain), principalName, properties);
    }

    String subjectType(final String domain) {
        return userDomain.equals(domain) ? SUBJECT_USER : SUBJECT_SERVICE;
    }

    /**
     * @param audience token audience
     * @param scopeDomains domains included in the token scope
     * @return token gate resource
     */
    public static Resource tokenResource(final String audience, final Collection<String> scopeDomains) {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("token_type", TOKEN_TYPE_ACCESS);
        properties.put("scope_domains", new ArrayList<>(new TreeSet<>(scopeDomains)));
        return new Resource(RESOURCE_TOKEN, audience, properties);
    }

    /**
     * @param domain role domain
     * @param role role name
     * @param defined whether the role is defined in Athenz
     * @param rbacGranted whether RBAC granted the role, null when RBAC is not consulted
     * @return role resource
     */
    public static Resource roleResource(final String domain, final String role, boolean defined,
            final Boolean rbacGranted) {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("domain", domain);
        properties.put("role", role);
        properties.put("defined", defined);
        putIfNotNull(properties, "rbac_granted", rbacGranted);
        return new Resource(RESOURCE_ROLE, domain + ":role." + role, properties);
    }

    /**
     * @param resource Athenz resource string as used by the ZTS authorizer
     * @return generic Athenz resource
     */
    public static Resource athenzResource(final String resource) {
        return new Resource(RESOURCE_ATHENZ, resource, null);
    }

    /**
     * @param name action name
     * @return action object
     */
    public static Action action(final String name) {
        return new Action(name, null);
    }

    /**
     * @param token validated token
     * @return the token claims that are safe to share with the PDP
     */
    public static Map<String, Object> tokenClaims(final OAuth2Token token) {
        Map<String, Object> claims = new LinkedHashMap<>();
        putIfNotNull(claims, "iss", token.getIssuer());
        putIfNotNull(claims, "sub", token.getSubject());
        putIfNotNull(claims, "aud", token.getAudience());
        putIfNotNull(claims, "scope", token.getClaim("scope"));
        putIfNotNull(claims, "client_id", token.getClaim("client_id"));
        putIfNotNull(claims, "jti", token.getJwtId());
        if (token.getExpiryTime() > 0) {
            claims.put("exp", token.getExpiryTime());
        }
        return claims;
    }

    static void putIfNotNull(final Map<String, Object> map, final String key, final Object value) {
        if (value != null) {
            map.put(key, value);
        }
    }
}
