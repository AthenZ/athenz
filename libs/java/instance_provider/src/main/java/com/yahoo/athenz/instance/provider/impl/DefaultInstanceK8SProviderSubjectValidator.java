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

import com.yahoo.athenz.instance.provider.AttrValidator;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;

import static com.yahoo.athenz.auth.AuthorityConsts.ATHENZ_PRINCIPAL_DELIMITER;
import static com.yahoo.athenz.instance.provider.InstanceProvider.ZTS_INSTANCE_ATTESTATION_DATA_SUBJECT;

public class DefaultInstanceK8SProviderSubjectValidator implements AttrValidator {
    @Override
    public boolean confirm(InstanceConfirmation confirmation) {
        if (confirmation == null || confirmation.getAttributes() == null) {
            return false;
        }
        String attestationDataSubject = confirmation.getAttributes().get(ZTS_INSTANCE_ATTESTATION_DATA_SUBJECT);
        String csrPrincipal = confirmation.getDomain() + ATHENZ_PRINCIPAL_DELIMITER + confirmation.getService();
        String idTokenSub = InstanceUtils.getServiceAccountNameFromIdTokenSubject(attestationDataSubject);
        return csrPrincipal.equals(idTokenSub);
    }
}
