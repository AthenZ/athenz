/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

import { selectUserPendingMembers } from './user';

export const thunkSelectPendingMembersList = (state, domainName) => {
    let domainPendingMembers = selectPendingMembersList(state, domainName);
    if (Object.keys(domainPendingMembers).length === 0) {
        domainPendingMembers = null;
    }
    return domainPendingMembers;
};

export const selectUserDomains = (state) => {
    return state.domains.domainsList ? state.domains.domainsList : [];
};

export const selectPersonalDomain = (state, domainName) => {
    return selectUserDomains(state)
        ? selectUserDomains(state).find((domain) => domain.name === domainName)
        : undefined;
};

export const selectBusinessServicesAll = (state) => {
    return state.domains.businessServicesAll
        ? state.domains.businessServicesAll
        : [];
};

export const selectAllDomainsList = (state) => {
    return state.domains && state.domains.allDomainsList
        ? state.domains.allDomainsList
        : [];
};

export const selectPendingMembersList = (state, domainName, view) => {
    if (view === 'domain') {
        return state.domains[domainName] &&
            state.domains[domainName].domainData &&
            state.domains[domainName].domainData.pendingMembersList
            ? state.domains[domainName].domainData.pendingMembersList
            : {};
    } else if (view === 'admin') {
        return selectUserPendingMembers(state);
    } else {
        return {};
    }
};

export const selectHeaderDetails = (state) => {
    return state.domains.headerDetails ? state.domains.headerDetails : {};
};

export const selectTimeZone = (state) => {
    return state.domains.timeZone ? state.domains.timeZone : 'UTC';
};

export const selectProductMasterLink = (state) => {
    return selectHeaderDetails(state) &&
        selectHeaderDetails(state).productMasterLink
        ? selectHeaderDetails(state).productMasterLink
        : {};
};

export const selectFeatureFlag = (state) => {
    return state.domains.featureFlag ? state.domains.featureFlag : false;
};
export const selectAuthorityAttributes = (state) => {
    return state.domains.authorityAttributes
        ? state.domains.authorityAttributes
        : {};
};

export const selectUserLink = (state) => {
    return state.domains.headerDetails && state.domains.headerDetails.userData
        ? state.domains.headerDetails.userData.userLink
        : {};
};
