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
 *
 */

package com.yahoo.athenz.common.server.msd.validator;

import com.yahoo.athenz.msd.TransportPolicyValidationRequest;
import com.yahoo.athenz.msd.TransportPolicyValidationStatus;
import org.testng.annotations.Test;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

public class NoOpTransportPolicyValidatorTest {

    @Test
    public void testNoOpValidator() {

        TransportPolicyValidatorFactory factory = NoOpTransportPolicyValidator::new;
        TransportPolicyValidator validator = factory.create();
        assertTrue(validator instanceof NoOpTransportPolicyValidator);
        TransportPolicyValidationRequest request = new TransportPolicyValidationRequest();
        assertEquals(validator.validateTransportPolicy(request).getStatus(), TransportPolicyValidationStatus.VALID);
    }
}
