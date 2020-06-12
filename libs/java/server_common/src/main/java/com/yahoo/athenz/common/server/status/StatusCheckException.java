package com.yahoo.athenz.common.server.status;

import static com.yahoo.athenz.common.server.rest.ResourceException.INTERNAL_SERVER_ERROR;
import static com.yahoo.athenz.common.server.rest.ResourceException.symbolForCode;

public class StatusCheckException extends Exception {
    private int httpCode;
    private String msg;

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
