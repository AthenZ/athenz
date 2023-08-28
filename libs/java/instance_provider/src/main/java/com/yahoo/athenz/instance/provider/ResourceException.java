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
package com.yahoo.athenz.instance.provider;

public class ResourceException extends RuntimeException {

    public final static int OK = 200;
    public final static int FORBIDDEN = 403;
    public final static int NOT_FOUND = 404;
    public final static int NOT_IMPLEMENTED = 501;
    public final static int GATEWAY_TIMEOUT = 504;
    public final static int BAD_REQUEST     = 400;

    final private int code;

    public ResourceException(int code, Object data) {
        this(code, data.toString());
    }

    public ResourceException(int code, String message) {
        super("ResourceException (" + code + "): " + message);
        this.code = code;
    }

    public int getCode() {
        return code;
    }
}
