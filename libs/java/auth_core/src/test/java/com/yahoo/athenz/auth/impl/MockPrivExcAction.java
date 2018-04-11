/*
 * Copyright 2016 Yahoo Inc.
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
package com.yahoo.athenz.auth.impl;

import java.security.PrivilegedExceptionAction;

import com.yahoo.athenz.auth.token.KerberosToken;

public class MockPrivExcAction implements PrivilegedExceptionAction<String> {

    private byte[] kerberosTicket;
    private String realm = System.getProperty(KerberosToken.KRB_PROP_TOKEN_PRIV_ACTION + "_TEST_REALM",
            KerberosToken.KRB_USER_REALM);

    public MockPrivExcAction(String kerberosTicket) {
        this(kerberosTicket.getBytes());
    }
    public MockPrivExcAction(byte[] kerberosTicket) {
        this.kerberosTicket = kerberosTicket;
    }

    @Override
    public String run() {
        return "myclient" + "@" + realm;
    }
}
