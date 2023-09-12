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

package com.yahoo.athenz.common.server.status;

import static com.yahoo.athenz.common.server.rest.ResourceException.INTERNAL_SERVER_ERROR;
import static com.yahoo.athenz.common.server.rest.ResourceException.symbolForCode;

public class StatusCheckException extends Exception {
    private final int httpCode;
    private final String msg;

    public StatusCheckException() {
        this.httpCode = INTERNAL_SERVER_ERROR;
        this.msg = symbolForCode(httpCode);
    }

    public StatusCheckException(int httpCode) {
        this.httpCode = httpCode;
        this.msg = symbolForCode(httpCode);
    }

    public StatusCheckException(int httpCode, String msg) {
        this.httpCode = httpCode;
        this.msg = msg;
    }

    public StatusCheckException(Throwable cause) {
        this(INTERNAL_SERVER_ERROR, cause.getMessage());
    }

    public String getMsg() {
        return msg;
    }

    public int getCode() {
        return httpCode;
    }
}
