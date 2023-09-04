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

package com.yahoo.athenz.common.server.http;

import org.apache.http.StatusLine;

public class HttpDriverResponse {
    private final int statusCode;
    private final String message;
    private final StatusLine statusLine;

    public HttpDriverResponse(int statusCode, String message, StatusLine statusLine) {
        this.statusCode = statusCode;
        this.message = message;
        this.statusLine = statusLine;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getMessage() {
        return message;
    }

    public StatusLine getStatusLine() {
        return statusLine;
    }
}
