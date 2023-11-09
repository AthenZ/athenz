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
    ADD_KEY_TO_STORE,
    ADD_SERVICE_HOST_TO_STORE,
    ADD_SERVICE_TO_STORE,
    ALLOW_PROVIDER_TEMPLATE_TO_STORE,
    DELETE_KEY_FROM_STORE,
    DELETE_SERVICE_FROM_STORE,
    DELETE_SERVICE_INSTANCE_FROM_STORE,
    LOAD_INSTANCES_TO_STORE,
    LOAD_PROVIDER_TO_STORE,
    LOAD_SERVICE_HEADER_DETAILS_TO_STORE,
    LOAD_SERVICES,
    RETURN_SERVICES,
} from '../actions/services';
import { deleteInstanceFromWorkloadDataDraft, getExpiryTime } from '../utils';
import produce from 'immer';
import { SERVICE_TYPE_DYNAMIC } from '../../components/constants/constants';
import { UPDATE_TAGS_TO_STORE } from '../actions/collections';

export const services = (state = {}, action) => {
    const { type, payload } = action;
    switch (type) {
        case LOAD_SERVICES: {
            const { services, domainName, expiry } = payload;
            return {
                domainName,
                expiry,
                services,
            };
        }
        case ADD_SERVICE_TO_STORE: {
            const { serviceData } = payload;
            let newState = produce(state, (draft) => {
                draft.services[serviceData.name] = serviceData;
            });
            return newState;
        }
        case DELETE_SERVICE_FROM_STORE: {
            const { serviceFullName } = payload;
            let newState = produce(state, (draft) => {
                delete draft.services[serviceFullName];
            });
            return newState;
        }
        case DELETE_SERVICE_INSTANCE_FROM_STORE: {
            const { serviceFullName, instanceId, category } = payload;
            if (category === SERVICE_TYPE_DYNAMIC) {
                let newState = produce(state, (draft) => {
                    let originalLen =
                        draft.services[serviceFullName].dynamicInstances
                            .workLoadData.length;
                    deleteInstanceFromWorkloadDataDraft(
                        draft.services[serviceFullName].dynamicInstances
                            .workLoadData,
                        instanceId,
                        category
                    );
                    if (
                        originalLen ===
                        draft.services[serviceFullName].dynamicInstances
                            .workLoadData.length +
                            1
                    ) {
                        draft.services[
                            serviceFullName
                        ].dynamicInstances.workLoadMeta.totalDynamic -= 1;
                        draft.services[
                            serviceFullName
                        ].dynamicInstances.workLoadMeta.totalRecords -= 1;
                        draft.services[
                            serviceFullName
                        ].dynamicInstances.workLoadMeta.totalHealthyDynamic -= 1;
                    }
                });
                return newState;
            } else {
                let newState = produce(state, (draft) => {
                    let originalLen =
                        draft.services[serviceFullName].staticInstances
                            .workLoadData.length;
                    deleteInstanceFromWorkloadDataDraft(
                        draft.services[serviceFullName].staticInstances
                            .workLoadData,
                        instanceId,
                        category
                    );
                    if (
                        originalLen ===
                        draft.services[serviceFullName].staticInstances
                            .workLoadData.length +
                            1
                    ) {
                        draft.services[
                            serviceFullName
                        ].staticInstances.workLoadMeta.totalStatic -= 1;
                        draft.services[
                            serviceFullName
                        ].staticInstances.workLoadMeta.totalRecords -= 1;
                    }
                });
                return newState;
            }
        }
        case DELETE_KEY_FROM_STORE: {
            const { serviceFullName, keyId } = payload;
            let newState = produce(state, (draft) => {
                delete draft.services[serviceFullName].publicKeys[keyId];
            });
            return newState;
        }
        case ADD_KEY_TO_STORE: {
            const { serviceFullName, keyId, keyValue } = payload;
            let newState = produce(state, (draft) => {
                draft.services[serviceFullName].publicKeys[keyId] = {
                    key: keyValue,
                    id: keyId,
                };
            });
            return newState;
        }
        case LOAD_PROVIDER_TO_STORE: {
            const { serviceFullName, provider, allProviders } = payload;
            let newState = produce(state, (draft) => {
                if (draft.allProviders === undefined) {
                    draft.allProviders = allProviders;
                }
                draft.services[serviceFullName].provider = provider;
                draft.services[serviceFullName].provider.expiry =
                    getExpiryTime();
            });
            return newState;
        }
        case ALLOW_PROVIDER_TEMPLATE_TO_STORE: {
            const { serviceFullName, providerId } = payload;
            let newState = produce(state, (draft) => {
                draft.services[serviceFullName].provider[providerId] = 'allow';
            });
            return newState;
        }
        case LOAD_INSTANCES_TO_STORE:
            const { serviceFullName, category, instances } = payload;
            let newState = state;
            if (category === SERVICE_TYPE_DYNAMIC) {
                newState = produce(state, (draft) => {
                    draft.services[serviceFullName].dynamicInstances =
                        instances;
                });
            } else {
                newState = produce(state, (draft) => {
                    draft.services[serviceFullName].staticInstances = instances;
                });
            }
            return newState;
        case LOAD_SERVICE_HEADER_DETAILS_TO_STORE: {
            const { serviceFullName, serviceHeaderDetails } = payload;
            let newState = produce(state, (draft) => {
                draft.services[serviceFullName].serviceHeaderDetails =
                    serviceHeaderDetails;
            });
            return newState;
        }
        case ADD_SERVICE_HOST_TO_STORE: {
            const { serviceFullName, host } = payload;
            let newState = produce(state, (draft) => {
                draft.services[
                    serviceFullName
                ].staticInstances.workLoadData.push(host);
                draft.services[
                    serviceFullName
                ].staticInstances.workLoadMeta.totalStatic += 1;
                draft.services[
                    serviceFullName
                ].staticInstances.workLoadMeta.totalRecords += 1;
            });
            return newState;
        }
        case UPDATE_TAGS_TO_STORE: {
            const { collectionName, collectionWithTags, category } = payload;
            let newState = state;
            if (category === 'service') {
                newState = produce(state, (draft) => {
                    draft.services[collectionName]
                        ? (draft.services[collectionName].tags =
                              collectionWithTags.tags)
                        : (draft.services[collectionName] = collectionWithTags);
                });
            }
            return newState;
        }
        case RETURN_SERVICES:
            return state;
        default:
            return state;
    }
};
