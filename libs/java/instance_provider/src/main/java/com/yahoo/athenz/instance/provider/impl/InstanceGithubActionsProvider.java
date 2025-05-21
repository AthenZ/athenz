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

import org.slf4j.LoggerFactory;

// Note: The keys include "ly" because GitHubInstanceProvider is already implemented
// and to avoid duplication in config keys.
public class InstanceGithubActionsProvider extends InstanceGithubActionsProviderCommon {
    static {
        LOGGER = LoggerFactory.getLogger(InstanceGithubActionsProvider.class);

        // Initialize the static variables with specific values for this subclass
        GITHUB_ACTIONS_PROP_PROVIDER_DNS_SUFFIX  = "athenz.zts.github_actions.provider_dns_suffix";
        GITHUB_ACTIONS_PROP_BOOT_TIME_OFFSET     = "athenz.zts.github_actions.boot_time_offset";
        GITHUB_ACTIONS_PROP_CERT_EXPIRY_TIME     = "athenz.zts.github_actions.cert_expiry_time";
        GITHUB_ACTIONS_PROP_ENTERPRISE           = "athenz.zts.github_actions.enterprise";
        GITHUB_ACTIONS_PROP_AUDIENCE             = "athenz.zts.github_actions.audience";
        GITHUB_ACTIONS_PROP_ISSUER               = "athenz.zts.github_actions.issuer";
        GITHUB_ACTIONS_PROP_JWKS_URI             = "athenz.zts.github_actions.jwks_uri";
    }
}
