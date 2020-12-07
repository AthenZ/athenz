/*
 * Copyright 2020 Yahoo Inc.
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
package com.yahoo.athenz.auth;

/**
 * Constants used by Authority classes
 */
public final class AuthorityConsts {

    // Athenz data model
    public static final char ATHENZ_PRINCIPAL_DELIMITER_CHAR = '.';
    public static final String ATHENZ_PRINCIPAL_DELIMITER = String.valueOf(ATHENZ_PRINCIPAL_DELIMITER_CHAR);
    public static final String ROLE_SEP = ":role.";
    public static final String GROUP_SEP = ":group.";

    // system properties
    public static final String ATHENZ_PROP_USER_DOMAIN = "athenz.user_domain";
    public static final String ATHENZ_PROP_RESTRICTED_OU = "athenz.crypto.restricted_ou";

    // prevent object creation
    private AuthorityConsts() {
    }

}
