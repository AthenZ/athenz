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
package com.yahoo.athenz.common.server.rest;

public class ResourceException extends RuntimeException {

    private static final long serialVersionUID = 2289910486634456175L;
    
    public final static int OK = 200;
    public final static int CREATED = 201;
    public final static int ACCEPTED = 202;
    public final static int NO_CONTENT = 204;
    public final static int MOVED_PERMANENTLY = 301;
    public final static int FOUND = 302;
    public final static int SEE_OTHER = 303;
    public final static int NOT_MODIFIED = 304;
    public final static int TEMPORARY_REDIRECT = 307;
    public final static int BAD_REQUEST = 400;
    public final static int UNAUTHORIZED = 401;
    public final static int FORBIDDEN = 403;
    public final static int NOT_FOUND = 404;
    public final static int CONFLICT = 409;
    public final static int GONE = 410;
    public final static int PRECONDITION_FAILED = 412;
    public final static int UNSUPPORTED_MEDIA_TYPE = 415;
    public final static int INTERNAL_SERVER_ERROR = 500;
    public final static int NOT_IMPLEMENTED = 501;
    public final static int SERVICE_UNAVAILABLE = 503;

    public static int codeForSymbol(String sym) {
        String symbol = sym.toUpperCase();
        if (symbol.contains("OK")) {
            return OK;
        } else if ("CREATED".equals(symbol)) {
            return CREATED;
        } else if ("ACCEPTED".equals(symbol)) {
            return ACCEPTED;
        } else if ("NO_CONTENT".equals(symbol)) {
            return NO_CONTENT;
        } else if ("MOVED_PERMANENTLY".equals(symbol)) {
            return MOVED_PERMANENTLY;
        } else if ("FOUND".equals(symbol)) {
            return FOUND;
        } else if ("SEE_OTHER".equals(symbol)) {
            return SEE_OTHER;
        } else if ("NOT_MODIFIED".equals(symbol)) {
            return NOT_MODIFIED;
        } else if ("TEMPORARY_REDIRECT".equals(symbol)) {
            return TEMPORARY_REDIRECT;
        } else if ("BAD_REQUEST".equals(symbol)) {
            return BAD_REQUEST;
        } else if ("UNAUTHORIZED".equals(symbol)) {
            return UNAUTHORIZED;
        } else if ("FORBIDDEN".equals(symbol)) {
            return FORBIDDEN;
        } else if ("NOT_FOUND".equals(symbol)) {
            return NOT_FOUND;
        } else if ("CONFLICT".equals(symbol)) {
            return CONFLICT;
        } else if ("GONE".equals(symbol)) {
            return GONE;
        } else if ("PRECONDITION_FAILED".equals(symbol)) {
            return PRECONDITION_FAILED;
        } else if ("INTERNAL_SERVER_ERROR".equals(symbol)) {
            return INTERNAL_SERVER_ERROR;
        } else if ("NOT_IMPLEMENTED".equals(symbol)) {
            return NOT_IMPLEMENTED;
        } else if ("UNSUPPORTED_MEDIA_TYPE".equals(symbol)) {
            return UNSUPPORTED_MEDIA_TYPE;
        } else if ("SERVICE_UNAVAILABLE".equals(symbol)) {
            return SERVICE_UNAVAILABLE;
        } else {
            try {
                return Integer.parseInt(sym);
            } catch (NumberFormatException ignored) {
            }
        }
        return 0;
    }

    public static String symbolForCode(int code) {
        switch (code) {
        case OK:
            return "OK";
        case CREATED:
            return "CREATED";
        case ACCEPTED:
            return "ACCEPTED";
        case NO_CONTENT:
            return "NO_CONTENT";
        case MOVED_PERMANENTLY:
            return "MOVED_PERMANENTLY";
        case FOUND:
            return "FOUND";
        case SEE_OTHER:
            return "SEE_OTHER";
        case NOT_MODIFIED:
            return "NOT_MODIFIED";
        case TEMPORARY_REDIRECT:
            return "TEMPORARY_REDIRECT";
        case BAD_REQUEST:
            return "BAD_REQUEST";
        case UNAUTHORIZED:
            return "UNAUTHORIZED";
        case FORBIDDEN:
            return "FORBIDDEN";
        case NOT_FOUND:
            return "NOT_FOUND";
        case CONFLICT:
            return "CONFLICT";
        case GONE:
            return "GONE";
        case PRECONDITION_FAILED:
            return "PRECONDITION_FAILED";
        case INTERNAL_SERVER_ERROR:
            return "INTERNAL_SERVER_ERROR";
        case NOT_IMPLEMENTED:
            return "NOT_IMPLEMENTED";
        case UNSUPPORTED_MEDIA_TYPE:
            return "UNSUPPORTED_MEDIA_TYPE";
        case SERVICE_UNAVAILABLE:
            return "SERVICE_UNAVAILABLE";
        }
        return null;
    }

    int code;
    Object data;

    public ResourceException(int code) {
        this(code, symbolForCode(code));
    }

    public ResourceException(int code, Object data) {
        super("ResourceException (" + code + "): " + data);
        this.code = code;
        this.data = data;
    }

    public int getCode() {
        return code;
    }

    public Object getData() {
        return data;
    }

    public <T> T getData(Class<T> cl) {
        return cl.cast(data);
    }
}
