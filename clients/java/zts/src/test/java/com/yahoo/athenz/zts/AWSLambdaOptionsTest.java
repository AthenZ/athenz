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

import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

public class AWSLambdaOptionsTest {

    @Test
    public void testAWSLambdaOptionsDefaults() {

        AWSLambdaOptions options = new AWSLambdaOptions();
        assertEquals(options.getKeyAlgorithm(), AWSLambdaOptions.KEY_ALGORITHM_RSA);
        assertEquals(options.getRsaKeySize(), AWSLambdaOptions.DEFAULT_RSA_KEY_SIZE);
        assertEquals(options.getEcCurveName(), AWSLambdaOptions.DEFAULT_EC_CURVE_NAME);

        assertFalse(options.isUseWebIdentityToken());
        assertNull(options.getWebIdentityAudience());
        assertEquals(options.getWebIdentitySigningAlgorithm(), AWSLambdaOptions.DEFAULT_SIGNING_ALGORITHM);
        assertEquals(options.getWebIdentityDurationSeconds(), AWSLambdaOptions.DEFAULT_DURATION_SECONDS);
    }

    @Test
    public void testAWSLambdaOptionsSetters() {

        AWSLambdaOptions options = new AWSLambdaOptions();

        options.setKeyAlgorithm(AWSLambdaOptions.KEY_ALGORITHM_EC);
        assertEquals(options.getKeyAlgorithm(), AWSLambdaOptions.KEY_ALGORITHM_EC);

        options.setRsaKeySize(4096);
        assertEquals(options.getRsaKeySize(), 4096);

        options.setEcCurveName("secp256r1");
        assertEquals(options.getEcCurveName(), "secp256r1");

        options.setUseWebIdentityToken(true);
        assertTrue(options.isUseWebIdentityToken());

        options.setWebIdentityAudience("https://zts.athenz.io");
        assertEquals(options.getWebIdentityAudience(), "https://zts.athenz.io");

        options.setWebIdentitySigningAlgorithm("RS256");
        assertEquals(options.getWebIdentitySigningAlgorithm(), "RS256");

        options.setWebIdentityDurationSeconds(600);
        assertEquals(options.getWebIdentityDurationSeconds(), 600);
    }
}
