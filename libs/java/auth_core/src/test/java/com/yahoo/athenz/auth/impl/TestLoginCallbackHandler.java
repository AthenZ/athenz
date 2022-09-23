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
package com.yahoo.athenz.auth.impl;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

/**
 * Password callback handler for resolving password/usernames for a JAAS login.
 */
class TestLoginCallbackHandler implements CallbackHandler {

    public TestLoginCallbackHandler() { 
        super();
    }
  
    public TestLoginCallbackHandler(String name, String password) { 
        super();
        this.username = name;
        if (password != null) {
            this.password = password;
        }
    }
  
    public TestLoginCallbackHandler(String password) { 
        super();
        this.password = password;
    }
  
    private String username;
    private String password = "orange2";

    /**
     * Handles the callbacks, and sets the user/password detail.
     * @param callbacks the callbacks to handle
     * @throws UnsupportedCallbackException if an input or output error occurs.
     */
    public void handle(Callback[] callbacks) throws UnsupportedCallbackException {

        for (Callback cback: callbacks) {
            if (cback instanceof NameCallback && username != null) {
                NameCallback nc = (NameCallback) cback;
                nc.setName(username);
            } else if (cback instanceof PasswordCallback) {
                PasswordCallback pc = (PasswordCallback) cback;
                pc.setPassword(password.toCharArray());
            } else {
                // other callbacks: AuthorizeCallback, ChoiceCallback, ConfirmationCallback, 
                // LanguageCallback, RealmCallback, RealmChoiceCallback, TextInputCallback, TextOutputCallback
                // what does our grid services usually do?
              
                throw new UnsupportedCallbackException(cback, "Unrecognized Callback");
            }
        }
    }
}
  
