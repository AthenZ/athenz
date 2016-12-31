/**
 * Copyright 2016 Yahoo Inc.
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
package com.yahoo.athenz.auth.util;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A utility class to validate various types.
 */
public class Validate {

    private static final String PRINCIPAL_REGEX = "((([a-zA-Z_][a-zA-Z0-9_-]*\\.)*[a-zA-Z_][a-zA-Z0-9_-]*):)?(([a-zA-Z_][a-zA-Z0-9_-]*\\.)*[a-zA-Z_][a-zA-Z0-9_-]*)";
    private static final String DOMAIN_REGEX = "([a-zA-Z_][a-zA-Z0-9_-]*\\.)*[a-zA-Z_][a-zA-Z0-9_-]*";
    
    private static Pattern principalPattern = Pattern.compile(PRINCIPAL_REGEX);
    private static Pattern domainPattern = Pattern.compile(DOMAIN_REGEX);

    /**
     * @param name a principal name to validate
     * @return true if the principal name is valid, false otherwise.
     */
    public static boolean principalName(String name) {
        Matcher matcher = principalPattern.matcher(name);
        return matcher.matches();
    }

    /**
     * @param name a domain name to validate
     * @return true if the domain name is valid, false otherwise.
     */
    public static boolean domainName(String name) {
        Matcher matcher = domainPattern.matcher(name);
        return matcher.matches();
    }
}

