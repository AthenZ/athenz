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

import API from '../../api';
import {
    loadDomainData,
    loadDomainHistoryToStore,
    returnDomainData,
    updateBusinessServiceInStore,
} from '../actions/domain-data';
import {
    loadingFailed,
    loadingInProcess,
    loadingSuccess,
} from '../actions/loading';
import { storeDomainData } from '../actions/domains';
import { createBellPendingMembers, getExpiryTime, isExpired } from '../utils';
import {
    getAuthorityAttributes,
    getFeatureFlag,
    getHeaderDetails,
} from './domains';
const debug = require('debug')('AthenzUI:redux:domain');

const loadAllDomainData = async (domainName, userName, dispatch) => {
    dispatch(loadingInProcess('getDomainData'));
    try {
        let bServicesParams = {
            category: 'domain',
            attributeName: 'businessService',
            userName: userName,
        };
        const domainData = await API().getDomain(domainName);
        const [
            isAwsTemplateApplied,
            domainPendingMembersList,
            businessServices,
        ] = await Promise.all([
            API().isAWSTemplateApplied(domainName),
            API().getPendingDomainMembersListByDomain(domainName),
            API().getMeta(bServicesParams),
            dispatch(getHeaderDetails()),
            dispatch(getAuthorityAttributes()),
            dispatch(getFeatureFlag()),
        ]);
        domainData.isAWSTemplateApplied = isAwsTemplateApplied;
        domainData.bellPendingMembers = createBellPendingMembers(
            domainPendingMembersList
        );

        let businessServiceOptions = [];
        if (businessServices.validValues) {
            businessServices.validValues.forEach((businessService) => {
                let bServiceOnlyId = businessService.substring(
                    0,
                    businessService.indexOf(':')
                );
                let bServiceOnlyName = businessService.substring(
                    businessService.indexOf(':') + 1
                );
                businessServiceOptions.push({
                    value: bServiceOnlyId,
                    name: bServiceOnlyName,
                });
            });
        }
        domainData.businessServices = businessServiceOptions;
        const expiry = getExpiryTime();
        dispatch(loadDomainData(domainData, domainName, expiry));
        dispatch(loadingSuccess('getDomainData'));
    } catch (e) {
        dispatch(loadingFailed('getDomainData'));
        debug('Failed getDomainData:', e);
    }
};

export const getDomainData =
    (domainName, userName) => async (dispatch, getState) => {
        if (getState().domainData.expiry) {
            if (getState().domainData.domainName !== domainName) {
                dispatch(storeDomainData(getState().domainData));
                if (
                    getState().domains[domainName] &&
                    getState().domains[domainName].domainData &&
                    !isExpired(getState().domains[domainName].domainData.expiry)
                ) {
                    dispatch(
                        loadDomainData(
                            getState().domains[domainName].domainData
                                .domainData,
                            domainName,
                            getState().domains[domainName].domainData.expiry
                        )
                    );
                } else {
                    await loadAllDomainData(domainName, userName, dispatch);
                }
            } else if (isExpired(getState().domainData.expiry)) {
                await loadAllDomainData(domainName, userName, dispatch);
            } else {
                dispatch(returnDomainData());
            }
        } else {
            await loadAllDomainData(domainName, userName, dispatch);
        }
    };

export const getDomainHistory =
    (domainName, startDate, endDate, _csrf, roleName = 'ALL') =>
    async (dispatch, getState) => {
        try {
            let history = await API().getHistory(
                domainName,
                roleName,
                startDate,
                endDate,
                _csrf
            );
            dispatch(loadDomainHistoryToStore(history));
            return Promise.resolve(history);
        } catch (error) {
            return Promise.reject(error);
        }
    };

export const updateBusinessService =
    (domainName, meta, auditMsg, csrf, category) =>
    async (dispatch, getState) => {
        try {
            await API().putMeta(
                domainName,
                domainName,
                meta,
                auditMsg,
                csrf,
                category
            );
            dispatch(updateBusinessServiceInStore(meta.businessService));
            return Promise.resolve();
        } catch (e) {
            return Promise.reject(e);
        }
    };
