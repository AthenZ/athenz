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

package com.yahoo.athenz.common.server.spiffe;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

public class SpiffeUriManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(SpiffeUriManager.class);

    public static final String ZTS_PROP_SPIFFE_URI_VALIDATOR_CLASSES = "athenz.zts.spiffe_uri_validator_classes";
    public static final String ZTS_DEFAULT_SPIFFE_URI_VALIDATOR_CLASSES = "com.yahoo.athenz.common.server.spiffe.impl.SpiffeUriTrustDomain,com.yahoo.athenz.common.server.spiffe.impl.SpiffeUriBasic";

    private final List<SpiffeUriValidator> validators;

    public SpiffeUriManager() {

        final String validatorClasses = System.getProperty(ZTS_PROP_SPIFFE_URI_VALIDATOR_CLASSES,
                ZTS_DEFAULT_SPIFFE_URI_VALIDATOR_CLASSES);

        validators = new ArrayList<>();
        String[] validatorClassList = validatorClasses.split(",");
        for (String validatorClass : validatorClassList) {
            SpiffeUriValidator validator = getValidator(validatorClass.trim());
            if (validator == null) {
                throw new IllegalArgumentException("Invalid spiffe uri validator: " + validatorClass);
            }
            validators.add(validator);
        }
    }

    SpiffeUriValidator getValidator(String className) {

        LOGGER.debug("Loading spiffe uri validator {}...", className);

        SpiffeUriValidator validator;
        try {
            validator = (SpiffeUriValidator) Class.forName(className).getDeclaredConstructor().newInstance();
        } catch (Exception ex) {
            LOGGER.error("Invalid validator class: {}", className, ex);
            return null;
        }
        return validator;
    }

    public boolean validateServiceCertUri(final String spiffeUri, final String domainName, final String serviceName,
            final String namespace) {

        for (SpiffeUriValidator validator : validators) {
            if (validator.validateServiceCertUri(spiffeUri, domainName, serviceName, namespace)) {
                return true;
            }
        }
        LOGGER.error("unable to validate service spiffe uri: {}, domainName: {}, serviceName: {}, namespace: {}",
                spiffeUri, domainName, serviceName, namespace);
        return false;
    }

    public boolean validateRoleCertUri(final String spiffeUri, final String domainName, final String roleName) {
        for (SpiffeUriValidator validator : validators) {
            if (validator.validateRoleCertUri(spiffeUri, domainName, roleName)) {
                return true;
            }
        }
        LOGGER.error("unable to validate role spiffe uri: {}, domainName: {}, roleName: {}",
                spiffeUri, domainName, roleName);
        return false;
    }
}
