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

import com.yahoo.athenz.auth.util.AthenzUtils;

import java.net.MalformedURLException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LogsParserUtils {

    private static class PatternType {
        public Pattern pattern;
        public String operation;

        public PatternType(Pattern pattern, final String operation) {
            this.pattern = pattern;
            this.operation = operation;
        }
    }

    private static final String DOMAIN_REGEX = "([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*";

    // regex: /domain/{domainName}/token
    private static final PatternType ROLE_TOKEN_PATTERN = new PatternType(
            Pattern.compile("/domain/(" + DOMAIN_REGEX + ")/token", Pattern.MULTILINE), "role-token");

    // regex: /domain/{domainName}/role/{roleName}/token
    private static final PatternType ROLE_CERT_OLD_PATTERN = new PatternType(
            Pattern.compile("/domain/(" + DOMAIN_REGEX + ")/role/", Pattern.MULTILINE), "role-cert");

    // regex: /access/domain/{domainName}/role/{roleName}/principal/{principal}
    private static final PatternType ACCESS_ROLE_PATTERN = new PatternType(
            Pattern.compile("/access/domain/(" + DOMAIN_REGEX + ")/role/", Pattern.MULTILINE), "access-check");

    // regex: /access/domain/{domainName}/principal/{principal}
    private static final PatternType ACCESS_PRINCIPAL_PATTERN = new PatternType(
            Pattern.compile("/access/domain/(" + DOMAIN_REGEX + ")/principal/", Pattern.MULTILINE), "access-check");

    // regex: /oauth2/token
    private static final PatternType OAUTH_TOKEN_PATTERN = new PatternType(
            Pattern.compile("/oauth2/token.*scope=(" + DOMAIN_REGEX + ").*", Pattern.MULTILINE), "access-token");

    // regex: (alternate domain for cross-domain trust relation)
    // /access/{action}?domain={domain}
    // /access/{action}/{resource}?domain={domain}
    private static final PatternType ACCESS_RESOURCE_ALT_DOMAIN_PATTERN = new PatternType(
            Pattern.compile("/access/.*domain=(" + DOMAIN_REGEX + ").*", Pattern.MULTILINE), "access-check");

    // regex: /access/{action}?resource={domain}:{resource}
    private static final PatternType ACCESS_RESOURCE_PATTERN_QUERY_PARAM = new PatternType(
            Pattern.compile("/access/.*resource=(" + DOMAIN_REGEX + ").*", Pattern.MULTILINE), "access-check");

    // regex: /access/{action}/{resource}
    private static final PatternType ACCESS_RESOURCE_PATTERN = new PatternType(
            Pattern.compile("/access/.*/(" + DOMAIN_REGEX + "):.*", Pattern.MULTILINE), "access-check");

    // regex: /rolecert?roleName={domain}:role.{role}
    private static final PatternType ROLE_CERT_PATTERN = new PatternType(
            Pattern.compile("/rolecert.roleName=(" + DOMAIN_REGEX + "):role.*", Pattern.MULTILINE), "role-cert");

    private static final PatternType[] PATTERNS = {ROLE_TOKEN_PATTERN, ROLE_CERT_OLD_PATTERN,
            ACCESS_ROLE_PATTERN, ACCESS_PRINCIPAL_PATTERN, OAUTH_TOKEN_PATTERN,
            ACCESS_RESOURCE_ALT_DOMAIN_PATTERN, ACCESS_RESOURCE_PATTERN_QUERY_PARAM,
            ACCESS_RESOURCE_PATTERN, ROLE_CERT_PATTERN};

    private static final String PROP_TTL = "auth_history_syncer.ttl";
    private static final String PROP_TTL_DEFAULT = "720"; // 30 days
    private static final Long EXPIRY_HOURS = Long.parseLong(
            System.getProperty(PROP_TTL, PROP_TTL_DEFAULT));
    private static final long EXPIRY_TIME = 3660 * EXPIRY_HOURS;

    public static AuthHistoryDynamoDBRecord getRecordFromLogEvent(String message) throws MalformedURLException {

        String[] split = message.split("\\s+");
        AuthHistoryDynamoDBRecord record = createRecordObject(split[6]);
        record.setPrincipalDomain(AthenzUtils.extractPrincipalDomainName(split[2]));
        record.setPrincipalName(AthenzUtils.extractPrincipalServiceName(split[2]));
        record.setEndpoint(split[5].substring(1) + " " + split[6]);
        record.setTimestamp(split[3].substring(1));
        record.setPrimaryKey(generatePrimaryKey(record.getUriDomain(), record.getPrincipalDomain(),
                record.getPrincipalName()));
        record.setTtl(System.currentTimeMillis() / 1000L + EXPIRY_TIME);
        return record;
    }

    public static String generatePrimaryKey(String uriDomain, String principalDomain, String principalName) {
        return uriDomain + ":" + principalDomain + ":" + principalName;
    }

    private static AuthHistoryDynamoDBRecord createRecordObject(final String endpoint) throws MalformedURLException {
        for (PatternType patternType : PATTERNS) {
            Matcher m = patternType.pattern.matcher(endpoint);
            if (m.find()) {
                AuthHistoryDynamoDBRecord record = new AuthHistoryDynamoDBRecord();
                record.setUriDomain(m.group(1));
                record.setOperation(patternType.operation);
                return record;
            }
        }

        throw new MalformedURLException("Failed to locate domain at endpoint: " + endpoint);
    }
}
