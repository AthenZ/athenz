/*
 * Copyright 2020 Yahoo Inc.
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

/**
 * Thrown when the corresponding certificate is invalid
 */
public class CertificateIdentityException extends Exception {

    private static final long serialVersionUID = -3287975953851497109L;

    public CertificateIdentityException() {
        super();
    }

    public CertificateIdentityException(String message) {
        super(message);
    }

    public CertificateIdentityException(Throwable cause) {
        super(cause);
    }

}
