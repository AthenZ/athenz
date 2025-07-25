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
package com.yahoo.athenz.instance.provider.impl;

import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import org.testng.annotations.Test;

import java.util.HashMap;
import java.util.Map;

import static com.yahoo.athenz.instance.provider.InstanceProvider.ZTS_INSTANCE_ATTESTATION_DATA_SUBJECT;
import static org.testng.Assert.*;

public class DefaultInstanceK8SProviderSubjectValidatorTest {

    @Test
    public void testConfirm() {
        DefaultInstanceK8SProviderSubjectValidator validator = new DefaultInstanceK8SProviderSubjectValidator();
        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("athenz");
        confirmation.setService("kubernetes");
        confirmation.setAttributes(new HashMap<>());
        confirmation.getAttributes().put(ZTS_INSTANCE_ATTESTATION_DATA_SUBJECT, "system:serviceaccount:namespace:athenz.kubernetes");
        assertTrue(validator.confirm(confirmation));

        confirmation.getAttributes().put(ZTS_INSTANCE_ATTESTATION_DATA_SUBJECT, "system:serviceaccount:namespace:kubernetes");
        assertFalse(validator.confirm(confirmation));
    }
}
