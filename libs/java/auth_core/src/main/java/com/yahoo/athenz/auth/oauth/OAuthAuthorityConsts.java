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

/**
 * Constant used by OAuth2 JWT access token Authority
 */
public final class OAuthAuthorityConsts {

    /*
     * Client ID mapping
     */
    public static final String CLIENT_ID_FIELD_DELIMITER = ":";
    public static final String CLIENT_ID_DELIMITER = ",";

    /*
     * System properties
     */
    public static final String JA_PROP_AUTHN_CHALLENGE_REALM = "authn_challenge_realm";
    // certificate
    public static final String JA_PROP_CERT_EXCLUDED_PRINCIPALS = "cert.excluded_principals";
    public static final String JA_PROP_CERT_EXCLUDE_ROLE_CERTIFICATES = "cert.exclude_role_certificates";
    // JWT parser
    public static final String JA_PROP_PARSER_FACTORY_CLASS = "parser_factory_class";
    // JWT validator
    public static final String JA_PROP_VERIFY_CERT_THUMBPRINT = "verify_cert_thumbprint";
    public static final String JA_PROP_CLAIM_ISS = "claim.iss";
    public static final String JA_PROP_CLAIM_AUD = "claim.aud";
    public static final String JA_PROP_CLAIM_SCOPE = "claim.scope";
    public static final String JA_PROP_AUTHORIZED_CLIENT_IDS_PATH = "authorized_client_ids_path";
    // general
    public static final String SYSTEM_PROP_PREFIX = "athenz.auth.oauth.jwt.";
    public static final String CSV_DELIMITER = ",";

    /*
     * OAuth
     */
    public static final String AUTH_HEADER = "Authorization";
    public static final String BEARER_TYPE = "bearer"; // BEARER_TYPE.toLowerCase()

    // prevent object creation
    private OAuthAuthorityConsts() {
    }

}
