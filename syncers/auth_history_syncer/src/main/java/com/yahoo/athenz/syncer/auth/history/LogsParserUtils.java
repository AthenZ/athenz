/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.syncer.auth.history;

import java.net.MalformedURLException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LogsParserUtils {
    private static final String DOMAIN_REGEX = "([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*";

    // regex:
    // /domain/{domainName}/token
    // /domain/{domainName}/role/{roleName}/token
    // /access/domain/{domainName}/role/{roleName}/principal/{principal}
    // /access/domain/{domainName}/principal/{principal}
    private static final Pattern DOMAIN_PATH_PARAM_PATTERN = Pattern.compile("/domain/(" + DOMAIN_REGEX + ")/(token|role/|principal/)", Pattern.MULTILINE);

    // regex: /oauth2/token
    private static final Pattern OAUTH_TOKEN_PATTERN = Pattern.compile("/oauth2/token.*scope=(" + DOMAIN_REGEX + ").*", Pattern.MULTILINE);

    // regex: (alternate domain for cross-domain trust relation)
    // /access/{action}?domain={domain}
    // /access/{action}/{resource}?domain={domain}
    private static final Pattern ACCESS_RESOURCE_ALT_DOMAIN_PATTERN = Pattern.compile("/access/.*domain=(" + DOMAIN_REGEX + ").*", Pattern.MULTILINE);

    // regex: /access/{action}?resource={domain}:{resource}
    private static final Pattern ACCESS_RESOURCE_PATTERN_QUERY_PARAM = Pattern.compile("/access/.*resource=(" + DOMAIN_REGEX + ").*", Pattern.MULTILINE);

    // regex: /access/{action}/{resource}
    private static final Pattern ACCESS_RESOURCE_PATTERN = Pattern.compile("/access/.*/(" + DOMAIN_REGEX + "):.*", Pattern.MULTILINE);

    // regex: /rolecert?roleName={domain}:role.{role}
    private static final Pattern ROLE_CERT_PATTERN = Pattern.compile("/rolecert.roleName=(" + DOMAIN_REGEX + "):role.*", Pattern.MULTILINE);

    private static final Pattern[] PATTERNS = {DOMAIN_PATH_PARAM_PATTERN, OAUTH_TOKEN_PATTERN, ACCESS_RESOURCE_ALT_DOMAIN_PATTERN, ACCESS_RESOURCE_PATTERN_QUERY_PARAM, ACCESS_RESOURCE_PATTERN, ROLE_CERT_PATTERN};

    private static final String PROP_TTL = "auth_history_syncer.ttl";
    private static final String PROP_TTL_DEFAULT = "720"; // 30 days
    private static final Long EXPIRY_HOURS = Long.parseLong(
            System.getProperty(PROP_TTL, PROP_TTL_DEFAULT));
    private static final long EXPIRY_TIME = 3660 * EXPIRY_HOURS;

    public static AuthHistoryDynamoDBRecord getRecordFromLogEvent(String message) throws MalformedURLException {
        String[] split = message.split("\\s+");
        String principalDomain = getPrincipalDomain(split[2]);
        String principalName = getPrincipalName(split[2]);
        String endpoint = split[5].substring(1) + " " + split[6];
        String timestamp = split[3].substring(1);
        String uriDomain = getDomainFromEndpoint(split[6]);
        String primaryKey = generatePrimaryKey(uriDomain, principalDomain, principalName);
        return new AuthHistoryDynamoDBRecord(primaryKey, uriDomain, principalDomain, principalName, endpoint, timestamp, System.currentTimeMillis() / 1000L + EXPIRY_TIME);
    }

    public static String generatePrimaryKey(String uriDomain, String principalDomain, String principalName) {
        return uriDomain + ":" + principalDomain + ":" + principalName;
    }

    private static String getDomainFromEndpoint(String endpoint) throws MalformedURLException {
        for (Pattern pattern : PATTERNS) {
            Matcher m = pattern.matcher(endpoint);
            if (m.find()) {
                return m.group(1);
            }
        }

        throw new MalformedURLException("Failed to locate domain at endpoint: " + endpoint);
    }


    private static String getPrincipalDomain(String principal) {
        int n = principal.lastIndexOf('.');
        if (n <= 0 || n == principal.length() - 1) {
            return null;
        }
        return principal.substring(0, n);
    }

    private static String getPrincipalName(String principal) {
        int n = principal.lastIndexOf('.');
        if (n <= 0 || n == principal.length() - 1) {
            return null;
        }
        return principal.substring(n + 1);
    }
}
