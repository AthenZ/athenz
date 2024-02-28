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
    addKeyToStore,
    addServiceHostToStore,
    addServiceToStore,
    allowProviderTemplateToStore,
    deleteKeyFromStore,
    deleteServiceFromStore,
    deleteServiceInstanceFromStore,
    loadInstancesToStore,
    loadProvidersToStore,
    loadServiceHeaderDetailsToStore,
    loadServices,
    returnServices,
} from '../actions/services';
import { storeServices } from '../actions/domains';
import {
    buildErrorForDoesntExistCase,
    buildErrorForDuplicateCase,
    getCurrentTime,
    getFullName,
    isExpired,
    listToMap,
} from '../utils';
import { getServicesApiCall } from './utils/services';
import {
    selectInstancesWorkLoadData,
    thunkSelectService,
    thunkSelectServices,
} from '../selectors/services';
import { roleDelimiter, serviceDelimiter } from '../config';
import {
    loadingFailed,
    loadingInProcess,
    loadingSuccess,
} from '../actions/loading';
import { thunkSelectRoles } from '../selectors/roles';
import { deleteRoleFromStore } from '../actions/roles';
import { getRoles } from './roles';
import {
    SERVICE_TYPE_DYNAMIC,
    SERVICE_TYPE_STATIC,
} from '../../components/constants/constants';
import { getFeatureFlag } from './domains';

export const addService =
    (domainName, service, _csrf) => async (dispatch, getState) => {
        service.name = service.name.toLowerCase();
        await dispatch(getServices(domainName));
        let serviceMap = thunkSelectServices(getState());
        if (
            serviceMap[getFullName(domainName, serviceDelimiter, service.name)]
        ) {
            return Promise.reject(
                buildErrorForDuplicateCase('Service', service.name)
            );
        } else {
            try {
                let addedService = await API().addService(
                    domainName,
                    service.name,
                    service.description,
                    service.providerEndpoint,
                    service.keyId,
                    service.keyValue,
                    _csrf,
                    true
                );
                addedService.publicKeys = addedService.publicKeys
                    ? listToMap(addedService.publicKeys, 'id')
                    : {};
                dispatch(addServiceToStore(addedService));
                return Promise.resolve();
            } catch (err) {
                return Promise.reject(err);
            }
        }
    };

export const deleteService =
    (domainName, serviceName, _csrf) => async (dispatch, getState) => {
        serviceName = serviceName.toLowerCase();
        await dispatch(getServices(domainName));
        let serviceMap = thunkSelectServices(getState());
        if (
            !(
                getFullName(domainName, serviceDelimiter, serviceName) in
                serviceMap
            )
        ) {
            return Promise.reject(
                buildErrorForDoesntExistCase('Service', serviceName)
            );
        }
        try {
            await API().deleteService(domainName, serviceName, _csrf);
            dispatch(
                deleteServiceFromStore(
                    getFullName(domainName, serviceDelimiter, serviceName)
                )
            );
            return Promise.resolve();
        } catch (err) {
            return Promise.reject(err);
        }
    };

export const deleteKey =
    (domainName, serviceName, deleteKeyId, _csrf) =>
    async (dispatch, getState) => {
        serviceName = serviceName.toLowerCase();
        try {
            await dispatch(getServices(domainName));
            let currService = thunkSelectService(
                getState(),
                domainName,
                serviceName
            );
            if (
                currService &&
                currService.publicKeys[deleteKeyId] === undefined
            ) {
                return Promise.reject(
                    buildErrorForDoesntExistCase('Key id', deleteKeyId)
                );
            }
            await API().deleteKey(domainName, serviceName, deleteKeyId, _csrf);
            dispatch(
                deleteKeyFromStore(
                    getFullName(domainName, serviceDelimiter, serviceName),
                    deleteKeyId
                )
            );
            return Promise.resolve();
        } catch (err) {
            return Promise.reject(err);
        }
    };

export const addKey =
    (domainName, serviceName, keyId, keyValue, _csrf) =>
    async (dispatch, getState) => {
        serviceName = serviceName.toLowerCase();
        await dispatch(getServices(domainName));
        let currService = thunkSelectService(
            getState(),
            domainName,
            serviceName
        );
        if (currService?.publicKeys && currService.publicKeys[keyId]) {
            return Promise.reject(buildErrorForDuplicateCase('Key id', keyId));
        }
        try {
            await API().addKey(domainName, serviceName, keyId, keyValue, _csrf);
            dispatch(
                addKeyToStore(
                    getFullName(domainName, serviceDelimiter, serviceName),
                    keyId,
                    keyValue
                )
            );
            return Promise.resolve();
        } catch (err) {
            return Promise.reject(err);
        }
    };

export const getServices = (domainName) => async (dispatch, getState) => {
    if (getState().services.expiry) {
        if (getState().services.domainName !== domainName) {
            dispatch(storeServices(getState().services));
            if (
                getState().domains[domainName] &&
                getState().domains[domainName].services &&
                !isExpired(getState().domains[domainName].services.expiry)
            ) {
                dispatch(
                    loadServices(
                        getState().domains[domainName].services.services,
                        domainName,
                        getState().domains[domainName].services.expiry
                    )
                );
            } else {
                await getServicesApiCall(domainName, dispatch);
            }
        } else if (isExpired(getState().services.expiry)) {
            await getServicesApiCall(domainName, dispatch);
        } else {
            dispatch(returnServices());
        }
    } else {
        await getServicesApiCall(domainName, dispatch);
    }
};

export const getProvider =
    (domainName, serviceName) => async (dispatch, getState) => {
        serviceName = serviceName.toLowerCase();
        await dispatch(getServices(domainName));
        let currService = thunkSelectService(
            getState(),
            domainName,
            serviceName
        );
        if (
            currService &&
            currService.provider &&
            !isExpired(currService.provider.expiry)
        ) {
            return Promise.resolve();
        } else {
            try {
                let data = await API().getProvider(domainName, serviceName);
                dispatch(
                    loadProvidersToStore(
                        getFullName(domainName, serviceDelimiter, serviceName),
                        data.provider,
                        data.allProviders
                    )
                );
                return Promise.resolve();
            } catch (err) {
                return Promise.reject(err);
            }
        }
    };

export const allowProviderTemplate =
    (domainName, serviceName, providerId, _csrf) =>
    async (dispatch, getState) => {
        serviceName = serviceName.toLowerCase();
        try {
            await dispatch(getProvider(domainName, serviceName));
            await API().allowProviderTemplate(
                domainName,
                serviceName,
                providerId,
                _csrf
            );
            dispatch(
                allowProviderTemplateToStore(
                    getFullName(domainName, serviceDelimiter, serviceName),
                    providerId
                )
            );
            return Promise.resolve();
        } catch (err) {
            return Promise.reject(err);
        }
    };

export const getServiceHeaderAndInstances =
    (domainName, serviceName, category) => async (dispatch, getState) => {
        serviceName = serviceName.toLowerCase();
        await dispatch(getServices(domainName));
        await dispatch(getServiceInstances(domainName, serviceName, category));
        await dispatch(getServiceHeaderDetails(domainName, serviceName));
        await dispatch(getFeatureFlag());
    };

export const getServiceInstances =
    (domainName, serviceName, category) => async (dispatch, getState) => {
        serviceName = serviceName.toLowerCase();
        let currService = thunkSelectService(
            getState(),
            domainName,
            serviceName
        );
        if (!currService || !currService.name) {
            return Promise.reject(
                buildErrorForDoesntExistCase('Service', serviceName)
            );
        }
        try {
            let instances = await API().getInstances(
                domainName,
                serviceName,
                category
            );
            dispatch(
                loadInstancesToStore(
                    getFullName(domainName, serviceDelimiter, serviceName),
                    category,
                    instances
                )
            );
        } catch (err) {
            return Promise.reject(err);
        }
    };

export const getServiceHeaderDetails =
    (domainName, serviceName) => async (dispatch, getState) => {
        serviceName = serviceName.toLowerCase();
        let currService = thunkSelectService(
            getState(),
            domainName,
            serviceName
        );
        if (currService && currService.name) {
            try {
                let data = await API().getServiceHeaderDetails();
                dispatch(
                    loadServiceHeaderDetailsToStore(
                        getFullName(domainName, serviceDelimiter, serviceName),
                        data
                    )
                );
            } catch (err) {
                return Promise.reject(err);
            }
        }
    };

export const addServiceHost =
    (domainName, serviceName, details, auditRef, _csrf) =>
    async (dispatch, getState) => {
        serviceName = serviceName.toLowerCase();
        try {
            await API().addServiceHost(
                domainName,
                serviceName,
                details,
                auditRef,
                _csrf
            );
            const staticInstances = await API().getInstances(
                domainName,
                serviceName,
                'static'
            );
            dispatch(
                loadInstancesToStore(
                    getFullName(domainName, serviceDelimiter, serviceName),
                    'static',
                    staticInstances
                )
            );
            return Promise.resolve();
        } catch (err) {
            return Promise.reject(err);
        }
    };

export const deleteInstance =
    (
        category,
        provider,
        domain,
        service,
        instanceId,
        deleteJustification,
        _csrf
    ) =>
    async (dispatch, getState) => {
        await dispatch(getServiceInstances(domain, service, category));
        let instancesData = selectInstancesWorkLoadData(
            getState(),
            domain,
            service,
            category
        );
        let instanceIdKey = category === SERVICE_TYPE_DYNAMIC ? 'uuid' : 'name';
        let instance = instancesData.filter((instance) => {
            return instance[instanceIdKey] === instanceId;
        });

        if (!Array.isArray(instance) || !instance.length) {
            return Promise.reject(
                buildErrorForDoesntExistCase('Service Instance', instanceId)
            );
        } else {
            try {
                await API().deleteInstance(
                    provider,
                    domain,
                    service,
                    instanceId,
                    category,
                    deleteJustification,
                    _csrf
                );
                dispatch(
                    deleteServiceInstanceFromStore(
                        getFullName(domain, serviceDelimiter, service),
                        instanceId,
                        category
                    )
                );
                return Promise.resolve();
            } catch (error) {
                return Promise.reject(error);
            }
        }
    };
