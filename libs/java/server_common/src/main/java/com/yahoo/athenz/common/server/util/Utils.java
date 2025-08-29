/*
 * Copyright The Athenz Authors.
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

package com.yahoo.athenz.common.server.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.auth.AuthorityConsts;
import com.yahoo.athenz.common.server.ServerResourceException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Utils {

    private static final Logger LOGGER = LoggerFactory.getLogger(Utils.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    /** Convert a value to JSON - or return a human-readable error if failed */
    public static String jsonSerializeForLog(Object value) {
        try {
            return OBJECT_MAPPER.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            return "=== Can't JSON-ize a " + value.getClass().getName() + " ===";
        }
    }

    public static ServerResourceException error(int code, String msg, String caller) {
        LOGGER.error("Error: {} code: {} message: {}", caller, code, msg);
        return new ServerResourceException(code, msg);
    }

    public static ServerResourceException requestError(String msg, String caller) {
        return error(ServerResourceException.BAD_REQUEST, msg, caller);
    }

    public static ServerResourceException unauthorizedError(String msg, String caller) {
        return error(ServerResourceException.UNAUTHORIZED, msg, caller);
    }

    public static ServerResourceException forbiddenError(String msg, String caller) {
        return error(ServerResourceException.FORBIDDEN, msg, caller);
    }

    public static ServerResourceException notFoundError(String msg, String caller) {
        return error(ServerResourceException.NOT_FOUND, msg, caller);
    }

    public static ServerResourceException internalServerError(String msg, String caller) {
        return error(ServerResourceException.INTERNAL_SERVER_ERROR, msg, caller);
    }

    public static ServerResourceException conflictError(String msg, String caller) {
        return error(ServerResourceException.CONFLICT, msg, caller);
    }

    public static String extractObjectName(String domainName, String fullName, String objType) {

        // generate prefix to compare with

        final String prefix = domainName + objType;
        if (!fullName.startsWith(prefix)) {
            return null;
        }
        return fullName.substring(prefix.length());
    }

    public static String extractRoleName(String domainName, String fullRoleName) {
        return extractObjectName(domainName, fullRoleName, AuthorityConsts.ROLE_SEP);
    }

    public static String extractGroupName(String domainName, String fullGroupName) {
        return extractObjectName(domainName, fullGroupName, AuthorityConsts.GROUP_SEP);
    }

    public static String extractPolicyName(String domainName, String fullPolicyName) {
        return extractObjectName(domainName, fullPolicyName, AuthorityConsts.POLICY_SEP);
    }

    public static String extractEntityName(String domainName, String fullEntityName) {
        return extractObjectName(domainName, fullEntityName, AuthorityConsts.ENTITY_SEP);
    }

    public static String extractServiceName(String domainName, String fullServiceName) {
        return extractObjectName(domainName, fullServiceName, ".");
    }

    public static String assertionDomainCheck(final String role, final String resource) {

        final int rsrcIdx = resource.indexOf(':');
        if (rsrcIdx <= 0) {
            return null;
        }

        final int roleIdx = role.indexOf(':');
        if (roleIdx <= 0) {
            return null;
        }

        if (rsrcIdx != roleIdx) {
            return null;
        }

        if (role.regionMatches(0, resource, 0, rsrcIdx)) {
            return resource.substring(0, rsrcIdx);
        }

        return null;
    }
}
