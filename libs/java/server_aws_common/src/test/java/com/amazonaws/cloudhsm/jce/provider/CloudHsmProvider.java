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
package com.amazonaws.cloudhsm.jce.provider;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.LoginException;
import java.security.AuthProvider;

/**
 * Test double for the AWS CloudHSM JCE provider so unit tests can exercise
 * {@code AwsCloudHsmClient} without the proprietary CloudHSM SDK.
 */
public class CloudHsmProvider extends AuthProvider {

    public CloudHsmProvider() {
        super("CloudHsmProvider", 1.0, "Athenz unit-test stub");
        put("KeyStore.CloudHsmProvider", StubKeyStoreSpi.class.getName());
    }

    @Override
    public void login(Subject subject, CallbackHandler handler) throws LoginException {
        try {
            PasswordCallback callback = new PasswordCallback("pin", false);
            handler.handle(new Callback[]{callback, new PasswordCallback("other", false)});
        } catch (Exception ex) {
            throw new LoginException(ex.getMessage());
        }
    }

    @Override
    public void logout() {
    }

    @Override
    public void setCallbackHandler(CallbackHandler handler) {
    }
}
