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

import {
    loadingFailed,
    loadingInProcess,
    loadingSuccess,
} from '../actions/loading';
import API from '../../api';
import {
    addDomainToUserDomainsList,
    deleteDomainFromUserDomainList,
    loadAllDomainsList,
    loadAuthorityAttributes,
    loadBusinessServicesAll,
    loadFeatureFlag,
    loadHeaderDetails,
    loadTimeZone,
    loadPendingDomainMembersList,
    loadUserDomainList,
    processGroupPendingMembersToStore,
    processRolePendingMembersToStore,
    returnAuthorityAttributes,
    returnBusinessServicesAll,
    returnDomainList,
    returnFeatureFlag,
    returnHeaderDetails,
    returnTimeZone,
} from '../actions/domains';
import { buildErrorForDuplicateCase, getFullName } from '../utils';
import { subDomainDelimiter } from '../config';
import { selectPersonalDomain } from '../selectors/domains';
import { updateBellPendingMember } from '../actions/domain-data';
import { getFullCollectionName } from './utils/collection';
const debug = require('debug')('AthenzUI:redux:domains');

export const getUserDomainsList = () => async (dispatch, getState) => {
    try {
        if (!getState().domains.domainsList) {
            dispatch(loadingInProcess('getUserDomainsList'));
            const domainsList = await API().listUserDomains();
            dispatch(loadUserDomainList(domainsList));
            dispatch(loadingSuccess('getUserDomainsList'));
        } else {
            dispatch(returnDomainList());
        }
    } catch (err) {
        // if error, set domainsList to empty array
        dispatch(loadUserDomainList([]));
        dispatch(loadingFailed('getUserDomainsList'));
        throw err;
    }
};

export const getHeaderDetails = () => async (dispatch, getState) => {
    if (getState().domains.headerDetails) {
        dispatch(returnHeaderDetails());
    } else {
        const headerDetails = await API().getHeaderDetails();
        dispatch(loadHeaderDetails(headerDetails));
    }
};

export const getTimeZone = () => async (dispatch, getState) => {
    if (getState().domains.timeZone) {
        dispatch(returnTimeZone());
    } else {
        const timeZone = await API().getTimeZone();
        dispatch(loadTimeZone(timeZone));
    }
};

export const getAuthorityAttributes = () => async (dispatch, getState) => {
    if (getState().domains.authorityAttributes) {
        dispatch(returnAuthorityAttributes());
    } else {
        const authorityAttributes = await API().getAuthorityAttributes();
        dispatch(loadAuthorityAttributes(authorityAttributes));
    }
};

export const getFeatureFlag = () => async (dispatch, getState) => {
    if (getState().domains.featureFlag) {
        dispatch(returnFeatureFlag());
    } else {
        const featureFlag = await API().getFeatureFlag();
        dispatch(loadFeatureFlag(featureFlag));
    }
};

export const getBusinessServicesAll = () => async (dispatch, getState) => {
    let bServicesParamsAll = {
        category: 'domain',
        attributeName: 'businessService',
    };
    if (getState().domains.businessServicesAll) {
        dispatch(returnBusinessServicesAll());
    } else {
        try {
            const allBusinessServices = await API().getMeta(bServicesParamsAll);
            let businessServiceOptionsAll = [];
            if (allBusinessServices && allBusinessServices.validValues) {
                allBusinessServices.validValues.forEach((businessService) => {
                    let bServiceOnlyId = businessService.substring(
                        0,
                        businessService.indexOf(':')
                    );
                    let bServiceOnlyName = businessService.substring(
                        businessService.indexOf(':') + 1
                    );
                    businessServiceOptionsAll.push({
                        value: bServiceOnlyId,
                        name: bServiceOnlyName,
                    });
                });
            }
            dispatch(loadBusinessServicesAll(businessServiceOptionsAll));
        } catch (e) {
            dispatch(loadingFailed('getBusinessServicesAll'));
            debug('Failed getBusinessServicesAll:', e);
        }
    }
};

export const createSubDomain =
    (parentDomain, subDomain, adminUser, _csrf) =>
    async (dispatch, getState) => {
        await dispatch(getUserDomainsList());
        const domainName = getFullName(
            parentDomain,
            subDomainDelimiter,
            subDomain
        );
        const domain = selectPersonalDomain(getState(), domainName);
        if (domain) {
            throw buildErrorForDuplicateCase('Domain', domainName);
        }
        await API().createSubDomain(parentDomain, subDomain, adminUser, _csrf);
        dispatch(addDomainToUserDomainsList(domainName));
        return Promise.resolve();
    };

export const createUserDomain =
    (userId, _csrf) => async (dispatch, getState) => {
        await API().createUserDomain(userId, _csrf);
        dispatch(addDomainToUserDomainsList('home.' + userId));
        return Promise.resolve();
    };

export const deleteSubDomain =
    (parentDomain, domain, auditRef, _csrf) => async (dispatch, getState) => {
        await API().deleteSubDomain(parentDomain, domain, auditRef, _csrf);
        dispatch(
            deleteDomainFromUserDomainList(
                getFullName(parentDomain, subDomainDelimiter, domain)
            )
        );
        return Promise.resolve();
    };

export const getAllDomainsList = () => async (dispatch, getState) => {
    if (
        getState().domains.allDomainsList === undefined ||
        getState().domains.allDomainsList.length === 0
    ) {
        dispatch(loadingInProcess('getAllDomainsList'));
        try {
            let domainsList = await API().listAllDomains();
            dispatch(loadAllDomainsList(domainsList));
            dispatch(loadingSuccess('getAllDomainsList'));
            return Promise.resolve();
        } catch (err) {
            dispatch(loadingFailed('getAllDomainsList'));
            throw err;
        }
    }
};

/**
 * pending members are stored in the domains object because it is not necessarily related to the current domain.
 * in the working domain we crated a bellPendingMembers object that it's job is the show if there are pending members in the current domain.
 */
export const getPendingDomainMembersListByDomain =
    (domainName) => async (dispatch, getState) => {
        if (domainName !== null) {
            try {
                dispatch(
                    loadingInProcess('getPendingDomainMembersListByDomain')
                );
                let pendingDomainMembersList =
                    await API().getPendingDomainMembersListByDomain(domainName);
                dispatch(
                    loadPendingDomainMembersList(
                        pendingDomainMembersList,
                        domainName
                    )
                );
                dispatch(loadingSuccess('getPendingDomainMembersListByDomain'));
                return Promise.resolve();
            } catch (err) {
                dispatch(loadingFailed('getPendingDomainMembersListByDomain'));
                throw err;
            }
        }
    };

export const processPendingMembers =
    (
        domainName,
        collectionName,
        memberName,
        auditRef,
        category,
        membership,
        _csrf
    ) =>
    async (dispatch, getState) => {
        try {
            await API().processPending(
                domainName,
                collectionName,
                memberName,
                auditRef,
                category,
                membership,
                _csrf
            );
            if (category === 'role') {
                dispatch(
                    processRolePendingMembersToStore(
                        domainName,
                        collectionName,
                        membership
                    )
                );
            } else if (category === 'group') {
                dispatch(
                    processGroupPendingMembersToStore(
                        domainName,
                        collectionName,
                        membership
                    )
                );
            }
            dispatch(
                updateBellPendingMember(
                    memberName,
                    getFullCollectionName(domainName, collectionName, category)
                )
            );
            return Promise.resolve();
        } catch (err) {
            throw err;
        }
    };
