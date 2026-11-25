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

package com.yahoo.athenz.common.server.pdp;

/**
 * Exception thrown by {@link ExternalPolicyDecisionPoint} implementations.
 * The code determines how ZTS reports the failure and applies its fail mode.
 */
public class ExternalPdpException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * Failure categories reported by PDP implementations.
     */
    public enum Code {
        UNAVAILABLE,
        TIMEOUT,
        INVALID_RESPONSE,
        UNSUPPORTED,
        INTERNAL
    }

    private final Code code;

    /**
     * @param code failure category
     * @param message failure description
     */
    public ExternalPdpException(final Code code, final String message) {
        super(message);
        this.code = code;
    }

    /**
     * @param code failure category
     * @param message failure description
     * @param cause underlying cause
     */
    public ExternalPdpException(final Code code, final String message, final Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public Code getCode() {
        return code;
    }
}
