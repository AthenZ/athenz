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
package com.yahoo.athenz.zts;

/**
 * AWSLambdaOptions carries the settings that control how
 * {@link ZTSClient#getAWSLambdaServiceCertificate(String, String, String, String, String, String, AWSLambdaOptions)}
 * generates the lambda function's private key and the attestation data
 * presented to ZTS. Pass null to use the defaults: a 2048-bit RSA private
 * key and STS AssumeRole temporary credentials as attestation data.
 */
public class AWSLambdaOptions {

    public static final String KEY_ALGORITHM_RSA = "RSA";
    public static final String KEY_ALGORITHM_EC = "EC";

    public static final int DEFAULT_RSA_KEY_SIZE = 2048;
    public static final String DEFAULT_EC_CURVE_NAME = "secp384r1";

    public static final String DEFAULT_SIGNING_ALGORITHM = "ES384";
    public static final int DEFAULT_DURATION_SECONDS = 300;

    private String keyAlgorithm = KEY_ALGORITHM_RSA;
    private int rsaKeySize = DEFAULT_RSA_KEY_SIZE;
    private String ecCurveName = DEFAULT_EC_CURVE_NAME;

    private boolean useWebIdentityToken;
    private String webIdentityAudience;
    private String webIdentitySigningAlgorithm = DEFAULT_SIGNING_ALGORITHM;
    private int webIdentityDurationSeconds = DEFAULT_DURATION_SECONDS;

    /**
     * Get the private key algorithm
     * @return keyAlgorithm either "RSA" or "EC"
     */
    public String getKeyAlgorithm() {
        return keyAlgorithm;
    }

    /**
     * Set the private key algorithm to generate for the lambda function's
     * identity. Must be either "RSA" (the default) or "EC".
     * @param keyAlgorithm key algorithm value
     */
    public void setKeyAlgorithm(String keyAlgorithm) {
        this.keyAlgorithm = keyAlgorithm;
    }

    /**
     * Get the RSA key size
     * @return rsaKeySize
     */
    public int getRsaKeySize() {
        return rsaKeySize;
    }

    /**
     * Set the size, in bits, of the RSA private key to generate when
     * keyAlgorithm is "RSA". Defaults to 2048.
     * @param rsaKeySize rsa key size in bits
     */
    public void setRsaKeySize(int rsaKeySize) {
        this.rsaKeySize = rsaKeySize;
    }

    /**
     * Get the EC curve name
     * @return ecCurveName
     */
    public String getEcCurveName() {
        return ecCurveName;
    }

    /**
     * Set the standard curve name (e.g. "secp256r1", "secp384r1") of the EC
     * private key to generate when keyAlgorithm is "EC". Defaults to "secp384r1".
     * @param ecCurveName ec curve name
     */
    public void setEcCurveName(String ecCurveName) {
        this.ecCurveName = ecCurveName;
    }

    /**
     * Check whether an AWS web identity token should be used as attestation data
     * @return useWebIdentityToken
     */
    public boolean isUseWebIdentityToken() {
        return useWebIdentityToken;
    }

    /**
     * Set whether to use an AWS-issued OIDC web identity token (JWT) as the
     * attestation data presented to ZTS, instead of STS AssumeRole temporary
     * credentials (the default).
     * @param useWebIdentityToken true to use a web identity token
     */
    public void setUseWebIdentityToken(boolean useWebIdentityToken) {
        this.useWebIdentityToken = useWebIdentityToken;
    }

    /**
     * Get the audience for the web identity token
     * @return webIdentityAudience
     */
    public String getWebIdentityAudience() {
        return webIdentityAudience;
    }

    /**
     * Set the audience for the web identity token. This is the intended
     * recipient of the token, typically the ZTS server url. If not specified,
     * the ZTS client's configured ZTS url is used.
     * @param webIdentityAudience audience value
     */
    public void setWebIdentityAudience(String webIdentityAudience) {
        this.webIdentityAudience = webIdentityAudience;
    }

    /**
     * Get the signing algorithm for the web identity token
     * @return webIdentitySigningAlgorithm
     */
    public String getWebIdentitySigningAlgorithm() {
        return webIdentitySigningAlgorithm;
    }

    /**
     * Set the signing algorithm for the web identity token. Must be either
     * "RS256" or "ES384". Defaults to "ES384".
     * @param webIdentitySigningAlgorithm signing algorithm value
     */
    public void setWebIdentitySigningAlgorithm(String webIdentitySigningAlgorithm) {
        this.webIdentitySigningAlgorithm = webIdentitySigningAlgorithm;
    }

    /**
     * Get the lifetime of the web identity token in seconds
     * @return webIdentityDurationSeconds
     */
    public int getWebIdentityDurationSeconds() {
        return webIdentityDurationSeconds;
    }

    /**
     * Set the lifetime of the web identity token in seconds. Must be between
     * 60 and 3600 (inclusive). Defaults to 300 (5 minutes).
     * @param webIdentityDurationSeconds duration in seconds
     */
    public void setWebIdentityDurationSeconds(int webIdentityDurationSeconds) {
        this.webIdentityDurationSeconds = webIdentityDurationSeconds;
    }
}
