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

package com.yahoo.athenz.zms_aws_domain_syncer;

import com.yahoo.athenz.zms.JWSDomain;
import com.yahoo.rdl.Timestamp;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.testng.Assert.*;

public class DomainValidatorTest {

    private final static String TESTROOT = "src/test/resources";

    @BeforeMethod
    public void beforeMethod() {
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH, TESTROOT);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_DEBUG, "true");
    }

    @Test
    public void testValidateJWSDomainValid() {

        DomainValidator domainValidator = new DomainValidator();

        JWSDomain jwsDomain = TestUtils.createJWSDomain("coretech", Timestamp.fromCurrentTime());
        assertTrue(domainValidator.validateJWSDomain(jwsDomain));
    }

    @Test
    public void testValidateJWSDomainInvalidSignature() {

        DomainValidator domainValidator = new DomainValidator();

        JWSDomain jwsDomain = TestUtils.createJWSDomain("coretech", Timestamp.fromCurrentTime());
        final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        jwsDomain.setSignature(encoder.encodeToString("unknown signature".getBytes(StandardCharsets.UTF_8)));

        assertFalse(domainValidator.validateJWSDomain(jwsDomain));
    }

    @Test
    public void testValidateJWSDomainUnknownKeyId() {

        DomainValidator domainValidator = new DomainValidator();

        JWSDomain jwsDomain = TestUtils.createJWSDomain("coretech", Timestamp.fromCurrentTime());
        final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        final String protectedHeader = "{\"kid\":\"unknown\",\"alg\":\"RS256\"}";
        jwsDomain.setProtectedHeader(encoder.encodeToString(protectedHeader.getBytes(StandardCharsets.UTF_8)));
        assertFalse(domainValidator.validateJWSDomain(jwsDomain));
    }

    @Test
    public void testValidateJWSDomainInvalidHeader() {

        DomainValidator domainValidator = new DomainValidator();

        JWSDomain jwsDomain = TestUtils.createJWSDomain("coretech", Timestamp.fromCurrentTime());
        jwsDomain.setProtectedHeader("invalid-base64-header");

        assertFalse(domainValidator.validateJWSDomain(jwsDomain));
    }

    @Test
    public void testValidateJWSDomainMissingKid() {

        DomainValidator domainValidator = new DomainValidator();

        JWSDomain jwsDomain = TestUtils.createJWSDomain("coretech", Timestamp.fromCurrentTime());
        final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        final String protectedHeader = "{\"alg\":\"RS256\"}";
        jwsDomain.setProtectedHeader(encoder.encodeToString(protectedHeader.getBytes(StandardCharsets.UTF_8)));

        assertFalse(domainValidator.validateJWSDomain(jwsDomain));
    }

    @Test
    public void testValidateJWSDomainInvalidBases64Signature() {

        DomainValidator domainValidator = new DomainValidator();

        JWSDomain jwsDomain = TestUtils.createJWSDomain("coretech", Timestamp.fromCurrentTime());
        jwsDomain.setSignature("invalid-base64-header");

        assertFalse(domainValidator.validateJWSDomain(jwsDomain));
    }

    @Test
    public void testExtractDomainNameInvalidJWSDomain() {

        DomainValidator domainValidator = new DomainValidator();
        JWSDomain jwsDomain = new JWSDomain().setPayload("invalid-payload");
        assertNull(domainValidator.extractDomainName(jwsDomain));
    }
}
