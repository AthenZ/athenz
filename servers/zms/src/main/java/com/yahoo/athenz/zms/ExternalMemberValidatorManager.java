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
package com.yahoo.athenz.zms;

import com.yahoo.athenz.auth.AuthorityConsts;
import com.yahoo.athenz.auth.ExternalMemberValidator;
import com.yahoo.athenz.zms.utils.ZMSUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static com.yahoo.athenz.zms.ZMSConsts.*;

public class ExternalMemberValidatorManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(ExternalMemberValidatorManager.class);

    private ScheduledExecutorService scheduledExecutor;
    private final DBService dbService;
    private final ConcurrentHashMap<String, ExternalMemberValidator> validators = new ConcurrentHashMap<>();
    private volatile Map<String, String> domainValidatorClasses = Collections.emptyMap();

    public ExternalMemberValidatorManager(final DBService dbService) {
        LOGGER.info("Initializing ExternalMemberValidatorManager...");
        this.dbService = dbService;
        refreshValidators();
        init();
    }

    private void init() {
        scheduledExecutor = Executors.newSingleThreadScheduledExecutor();
        long frequencyMinutes = Long.parseLong(
                System.getProperty(ZMS_PROP_EXTERNAL_MEMBER_VALIDATOR_FREQUENCY_MINUTES,
                        ZMS_PROP_EXTERNAL_MEMBER_VALIDATOR_FREQUENCY_DEFAULT));
        scheduledExecutor.scheduleAtFixedRate(this::refreshValidators, frequencyMinutes,
            frequencyMinutes, TimeUnit.MINUTES);
    }

    public void shutdown() {
        if (scheduledExecutor != null) {
            scheduledExecutor.shutdownNow();
        }
    }

    public void refreshValidators() {

        LOGGER.info("Refreshing external member validators from datastore");

        Map<String, String> currentDomainValidators;
        try {
            currentDomainValidators = dbService.getDomainsWithExternalMemberValidator();
        } catch (Exception ex) {
            LOGGER.error("Unable to fetch domains with external member validators: {}", ex.getMessage());
            return;
        }

        for (String domainName : validators.keySet()) {
            if (!currentDomainValidators.containsKey(domainName)) {
                LOGGER.info("Removing external member validator for domain: {}", domainName);
                validators.remove(domainName);
            }
        }

        for (Map.Entry<String, String> entry : currentDomainValidators.entrySet()) {
            final String domainName = entry.getKey();
            final String validatorClass = entry.getValue();

            final String existingClass = domainValidatorClasses.get(domainName);
            if (validatorClass.equals(existingClass) && validators.containsKey(domainName)) {
                continue;
            }

            ExternalMemberValidator validator = newValidatorInstance(validatorClass);
            if (validator != null) {
                LOGGER.info("Loaded external member validator {} for domain: {}", validatorClass, domainName);
                validators.put(domainName, validator);
            } else {
                LOGGER.error("Failed to instantiate external member validator {} for domain: {}",
                        validatorClass, domainName);
                validators.remove(domainName);
            }
        }

        domainValidatorClasses = currentDomainValidators;
        LOGGER.info("External member validator refresh complete. Active validators for {} domains", validators.size());
    }

    ExternalMemberValidator newValidatorInstance(final String className) {
        try {
            Class<?> clazz = Class.forName(className);
            return (ExternalMemberValidator) clazz.getDeclaredConstructor().newInstance();
        } catch (Exception ex) {
            LOGGER.error("Unable to instantiate external member validator class {}: {}",
                    className, ex.getMessage());
            return null;
        }
    }

    /**
     * Validate a member for the given domain. If the domain does not have
     * an external member validator available, or the member is not valid,
     * a bad request ResourceException is thrown.
     * @param domainName the domain to validate in
     * @param memberName the member name to validate
     * @param caller the caller method name for error reporting
     */
    public void validateMember(final String domainName, final String memberName, final String caller) {

        // we need to separate the external member prefix from the member name
        // and only pass the member name to the external resource validator
        // we'll check for the missing separator though we should never get there
        // since the server has already validated the format of the external member name

        int sepIdx = memberName.indexOf(AuthorityConsts.EXT_SEP);
        if (sepIdx == -1) {
            throw ZMSUtils.requestError("Principal " + memberName + " is not valid", caller);
        }

        final String extDomainName = memberName.substring(0, sepIdx);
        final String extMemberName = memberName.substring(sepIdx + AuthorityConsts.EXT_SEP.length());

        ExternalMemberValidator validator = validators.get(extDomainName);
        if (validator == null) {
            throw ZMSUtils.requestError("External member validator for domain "
                    + extDomainName + " is not available", caller);
        }
        if (!validator.validateMember(domainName, extMemberName)) {
            throw ZMSUtils.requestError("Member " + extMemberName
                    + " is not valid according to the external member validator for domain "
                    + domainName, caller);
        }
    }

    /**
     * Returns an unmodifiable set of domain names that have an external
     * member validator configured.
     * @return unmodifiable set of domain names with active validators
     */
    public Set<String> getDomainNamesWithValidator() {
        return Collections.unmodifiableSet(validators.keySet());
    }

    Map<String, ExternalMemberValidator> getValidators() {
        return validators;
    }

    Map<String, String> getDomainValidatorClasses() {
        return domainValidatorClasses;
    }
}
