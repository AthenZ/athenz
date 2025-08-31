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

package io.athenz.syncer.common.zms;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.yahoo.athenz.zms.DomainData;

@JsonSerialize
public class DomainState {
    private String domain;
    private String modified;
    private long fetchTime;

    public long getFetchTime() {
        return fetchTime;
    }
    public void setFetchTime(long fetchTime) {
        this.fetchTime = fetchTime;
    }
    public String getDomain() {
        return domain;
    }
    public void setDomain(String domain) {
        this.domain = domain;
    }
    public String getModified() {
        return modified;
    }
    public void setModified(String modified) {
        this.modified = modified;
    }

    public static DomainState getDomainState(final DomainData domData, long fetchTime) {
        DomainState domainState = new DomainState();
        domainState.setDomain(domData.getName());
        domainState.setModified(domData.getModified().toString());
        domainState.setFetchTime(fetchTime);
        return domainState;
    }
}
