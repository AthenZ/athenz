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
package com.yahoo.athenz.auth.oauth.util;

import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import jakarta.servlet.http.HttpServletRequest;
import com.yahoo.athenz.auth.oauth.OAuthAuthorityConsts;

/**
 * Utility class for JwtAuthority
 */
public class OAuthAuthorityUtils {

    /**
     * get system properties with JwtAuthority prefix
     * @param  key property name
     * @param  def default value
     * @return     system property value set
     */
    public static String getProperty(String key, String def) {
        return System.getProperty(OAuthAuthorityConsts.SYSTEM_PROP_PREFIX + key, def);
    }

    /**
     * convert CSV string to Set
     * @param  csv       CSV string
     * @param  delimiter CSV delimiter
     * @return           corresponding Set object of the CSV string, or null if CSV is null or empty
     */
    public static Set<String> csvToSet(String csv, String delimiter) {
        if (csv == null || csv.isEmpty()) {
            return null;
        }
        Set<String> set = new HashSet<>();
        if (delimiter == null || delimiter.isEmpty()) {
            set.add(csv);
        } else {
            Collections.addAll(set, csv.split(delimiter));
        }
        return set;
    }

    /**
     * Extract the OAuth bearer token from a header.
     * from: https://github.com/spring-projects/spring-security-oauth/blob/master/spring-security-oauth2/src/main/java/org/springframework/security/oauth2/provider/authentication/BearerTokenExtractor.java
     * @param request the request
     * @return        the token, or null if no OAuth authorization header was supplied
     */
    public static String extractHeaderToken(HttpServletRequest request) {
        Enumeration<String> headers = request.getHeaders(OAuthAuthorityConsts.AUTH_HEADER);
        while (headers.hasMoreElements()) {
            // typically there is only one (most servers enforce that)
            String value = headers.nextElement();
            if ((value.toLowerCase().startsWith(OAuthAuthorityConsts.BEARER_TYPE))) {
                String authHeaderValue = value.substring(OAuthAuthorityConsts.BEARER_TYPE.length()).trim();
                int commaIndex = authHeaderValue.indexOf(',');
                if (commaIndex > 0) {
                    authHeaderValue = authHeaderValue.substring(0, commaIndex);
                }
                return authHeaderValue;
            }
        }

        return null;
    }

    // prevent object creation
    private OAuthAuthorityUtils() {
    }

}
