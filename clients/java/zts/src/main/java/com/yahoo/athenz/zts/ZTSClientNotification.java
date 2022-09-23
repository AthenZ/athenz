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

package com.yahoo.athenz.zts;

import java.util.Objects;

public class ZTSClientNotification {
    private String ztsURL;
    private String role;
    private String type;
    private long expiration;
    private String message;
    private String domain;
    private boolean isInvalidToken;

    public ZTSClientNotification(String ztsURL, String role, String type, long expiration, boolean isInvalid, String domain) {
        this.ztsURL = ztsURL;
        this.role = role;
        this.type = type;
        this.expiration = expiration;
        this.isInvalidToken = isInvalid;
        this.domain = domain;

        this.message = "Fail to get token of type " + this.type + ". ";
        if (this.isInvalidToken) {
            this.message += " Will not re-attempt to fetch token as token is invalid.";
        }
    }

    public String getZtsURL() {
        return ztsURL;
    }

    public String getRole() {
        return role;
    }

    public String getType() {
        return type;
    }

    public long getExpiration() {
        return expiration;
    }

    public boolean getIsInvalidToken() {
        return isInvalidToken;
    }

    public String getMessage() {
        return message;
    }

    public String getDomain() {
        return domain;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        ZTSClientNotification that = (ZTSClientNotification) o;
        return ztsURL.equals(that.ztsURL) &&
                Objects.equals(domain, that.domain) &&
                Objects.equals(role, that.role) &&
                Objects.equals(type, that.type) &&
                expiration == that.expiration &&
                isInvalidToken == that.isInvalidToken &&
                message.equals(that.message);
    }

    @Override
    public int hashCode() {
        return Objects.hash(ztsURL, domain, role, type, expiration, isInvalidToken, message);
    }
}
