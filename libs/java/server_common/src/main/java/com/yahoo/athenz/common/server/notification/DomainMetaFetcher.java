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

package com.yahoo.athenz.common.server.notification;

import com.yahoo.athenz.common.server.db.DomainProvider;
import com.yahoo.athenz.zms.Domain;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DomainMetaFetcher {

    private static final Logger LOGGER = LoggerFactory.getLogger(DomainMetaFetcher.class);

    private final DomainProvider domainProvider;

    public DomainMetaFetcher(DomainProvider domainProvider) {
        this.domainProvider = domainProvider;
    }

    public NotificationDomainMeta getDomainMeta(String domainName, boolean masterCopy) {

        NotificationDomainMeta domainMeta = null;
        if (domainProvider == null) {
            return domainMeta;
        }

        try {
            Domain domain = domainProvider.getDomain(domainName, masterCopy);
            if (domain == null) {
                return domainMeta;
            }
            domainMeta = new NotificationDomainMeta(domainName);
            domainMeta.setSlackChannel(domain.getSlackChannel());
        } catch (Exception ex) {
            LOGGER.error("unable to fetch domain meta for domain: {} error: {}",
                    domainName, ex.getMessage(), ex);
        }

        return domainMeta;
    }
}
