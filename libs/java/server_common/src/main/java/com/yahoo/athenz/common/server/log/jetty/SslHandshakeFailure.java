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

package com.yahoo.athenz.common.server.log.jetty;

import org.eclipse.jetty.util.StringUtil;

import javax.net.ssl.SSLHandshakeException;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.regex.Pattern;

/**
 * Categorizes instances of {@link SSLHandshakeException}
 */
enum SslHandshakeFailure {
    INCOMPATIBLE_PROTOCOLS(
            "INCOMPATIBLE_CLIENT_PROTOCOLS",
            "(Client requested protocol \\S+? is not enabled or supported in server context" +
                    "|The client supported protocol versions \\[\\S+?\\] are not accepted by server preferences \\[\\S+?\\])"),
    INCOMPATIBLE_CIPHERS(
            "INCOMPATIBLE_CLIENT_CIPHER_SUITES",
            "no cipher suites in common"),
    MISSING_CLIENT_CERT(
            "MISSING_CLIENT_CERTIFICATE",
            "Empty server certificate chain"),
    EXPIRED_CLIENT_CERTIFICATE(
            "EXPIRED_CLIENT_CERTIFICATE",
            // Note: this pattern will match certificates with too late notBefore as well
            "PKIX path validation failed: java.security.cert.CertPathValidatorException: validity check failed"),
    INVALID_CLIENT_CERT(
            "INVALID_CLIENT_CERTIFICATE",
            "(PKIX path (building|validation) failed: .+)|(Invalid CertificateVerify signature)");

    private final String failureType;
    private final Predicate<String> messageMatcher;

    SslHandshakeFailure(String failureType, String messagePattern) {
        this.failureType = failureType;
        Pattern compiledPattern = Pattern.compile(messagePattern);
        this.messageMatcher = (s) -> compiledPattern.matcher(s).matches();
    }

    String failureType() {
        return failureType;
    }

    static Optional<SslHandshakeFailure> fromSslHandshakeException(SSLHandshakeException exception) {
        String message = exception.getMessage();
        if (StringUtil.isEmpty(message)) {
            return Optional.empty();
        }
        for (SslHandshakeFailure failure : values()) {
            if (failure.messageMatcher.test(message)) {
                return Optional.of(failure);
            }
        }
        return Optional.empty();
    }
}
