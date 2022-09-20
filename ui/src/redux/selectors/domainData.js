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
import { selectHeaderDetails } from './domains';

export const selectDomainData = (state) => {
    return state.domainData.domainData ? state.domainData.domainData : {};
};

export const selectDomainAuditEnabled = (state) => {
    return selectDomainData(state).auditEnabled
        ? selectDomainData(state).auditEnabled
        : false;
};

export const selectDomainTags = (state) => {
    return selectDomainData(state).tags ? selectDomainData(state).tags : {};
};

export const selectBellMembers = (state) => {
    return selectDomainData(state) && selectDomainData(state).bellPendingMembers
        ? selectDomainData(state).bellPendingMembers
        : {};
};

export const selectHistoryRows = (state) => {
    return selectDomainData(state).history
        ? selectDomainData(state).history
        : [];
};

// TODO - need to test it
export const selectBusinessServices = (state) => {
    return selectDomainData(state).businessServices
        ? selectDomainData(state).businessServices
        : [];
};
