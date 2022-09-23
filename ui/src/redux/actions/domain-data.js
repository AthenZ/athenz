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

export const LOAD_DOMAIN_DATA = 'LOAD_DOMAIN_DATA';
export const loadDomainData = (domainData, domainName, expiry) => ({
    type: LOAD_DOMAIN_DATA,
    payload: { domainData, domainName, expiry },
});

export const LOAD_DOMAIN_HISTORY_TO_STORE = 'LOAD_DOMAIN_HISTORY_TO_STORE';
export const loadDomainHistoryToStore = (history) => ({
    type: LOAD_DOMAIN_HISTORY_TO_STORE,
    payload: { history },
});

export const RETURN_DOMAIN_DATA = 'RETURN_DOMAIN_DATA';
export const returnDomainData = () => ({
    type: RETURN_DOMAIN_DATA,
});

export const UPDATE_BELL_PENDING_MEMBERS = 'UPDATE_BELL_PENDING_MEMBERS';
export const updateBellPendingMember = (memberName, collection) => ({
    type: UPDATE_BELL_PENDING_MEMBERS,
    payload: { memberName, collection },
});

export const UPDATE_BUSINESS_SERVICE_IN_STORE =
    'UPDATE_BUSINESS_SERVICE_IN_STORE';
export const updateBusinessServiceInStore = (businessServiceName) => ({
    type: UPDATE_BUSINESS_SERVICE_IN_STORE,
    payload: { businessServiceName },
});
