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
package com.yahoo.athenz.auth.util;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A utility class to validate various types.
 */
public class Validate {

    // these values must match the patters defined in the ZMS RDL:
    //      core/zms/src/main/rdl/Names.tdl

    private static final String PRINCIPAL_REGEX = "((([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*):)?(([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*)";
    private static final String DOMAIN_REGEX = "([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*";
    private static final String SIMPLE_NAME_REGEX = "[a-zA-Z0-9_][a-zA-Z0-9_-]*";

    private static final Pattern PRINCIPAL_PATTERN = Pattern.compile(PRINCIPAL_REGEX);
    private static final Pattern DOMAIN_PATTERN = Pattern.compile(DOMAIN_REGEX);
    private static final Pattern SIMPLE_NAME_PATTERN = Pattern.compile(SIMPLE_NAME_REGEX);

    /**
     * @param name a principal name to validate
     * @return true if the principal name is valid, false otherwise.
     */
    public static boolean principalName(final String name) {
        if (name == null || name.isEmpty()) {
            return false;
        }
        Matcher matcher = PRINCIPAL_PATTERN.matcher(name);
        return matcher.matches();
    }

    /**
     * @param name a domain name to validate
     * @return true if the domain name is valid, false otherwise.
     */
    public static boolean domainName(final String name) {
        if (name == null || name.isEmpty()) {
            return false;
        }
        Matcher matcher = DOMAIN_PATTERN.matcher(name);
        return matcher.matches();
    }

    /**
     * @param name a simple name to validate
     * @return true if the name is valid, false otherwise.
     */
    public static boolean simpleName(final String name) {
        if (name == null || name.isEmpty()) {
            return false;
        }
        Matcher matcher = SIMPLE_NAME_PATTERN.matcher(name);
        return matcher.matches();
    }
}

