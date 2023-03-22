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

export const LOAD_SERVICES = 'LOAD_SERVICES';
export const loadServices = (services, domainName, expiry) => ({
    type: LOAD_SERVICES,
    payload: { services: services, domainName: domainName, expiry: expiry },
});

export const RETURN_SERVICES = 'RETURN_SERVICES';
export const returnServices = () => ({
    type: RETURN_SERVICES,
});

export const ADD_SERVICE_TO_STORE = 'ADD_SERVICE_TO_STORE';
export const addServiceToStore = (serviceData) => ({
    type: ADD_SERVICE_TO_STORE,
    payload: {
        serviceData: serviceData,
    },
});

export const DELETE_SERVICE_FROM_STORE = 'DELETE_SERVICE_FROM_STORE';
export const deleteServiceFromStore = (serviceFullName) => ({
    type: DELETE_SERVICE_FROM_STORE,
    payload: {
        serviceFullName: serviceFullName,
    },
});

export const DELETE_KEY_FROM_STORE = 'DELETE_KEY_FROM_STORE';
export const deleteKeyFromStore = (serviceFullName, keyId) => ({
    type: DELETE_KEY_FROM_STORE,
    payload: {
        serviceFullName: serviceFullName,
        keyId: keyId,
    },
});
export const ADD_KEY_TO_STORE = 'ADD_KEY_TO_STORE';
export const addKeyToStore = (serviceFullName, keyId, keyValue) => ({
    type: ADD_KEY_TO_STORE,
    payload: {
        serviceFullName,
        keyId,
        keyValue,
    },
});

export const LOAD_PROVIDER_TO_STORE = 'LOAD_PROVIDER_TO_STORE';
export const loadProvidersToStore = (
    serviceFullName,
    provider,
    allProviders
) => ({
    type: LOAD_PROVIDER_TO_STORE,
    payload: {
        serviceFullName,
        provider,
        allProviders,
    },
});

export const ALLOW_PROVIDER_TEMPLATE_TO_STORE =
    'ALLOW_PROVIDER_TEMPLATE_TO_STORE';
export const allowProviderTemplateToStore = (serviceFullName, providerId) => ({
    type: ALLOW_PROVIDER_TEMPLATE_TO_STORE,
    payload: {
        serviceFullName,
        providerId,
    },
});

export const LOAD_INSTANCES_TO_STORE = 'LOAD_INSTANCES_TO_STORE';
export const loadInstancesToStore = (serviceFullName, category, instances) => ({
    type: LOAD_INSTANCES_TO_STORE,
    payload: {
        serviceFullName,
        category,
        instances,
    },
});

export const LOAD_SERVICE_HEADER_DETAILS_TO_STORE =
    'LOAD_SERVICE_HEADER_DETAILS_TO_STORE';
export const loadServiceHeaderDetailsToStore = (
    serviceFullName,
    serviceHeaderDetails
) => ({
    type: LOAD_SERVICE_HEADER_DETAILS_TO_STORE,
    payload: {
        serviceFullName,
        serviceHeaderDetails,
    },
});

export const ADD_SERVICE_HOST_TO_STORE = 'ADD_SERVICE_HOST_TO_STORE';
export const addServiceHostToStore = (serviceFullName, host) => ({
    type: ADD_SERVICE_HOST_TO_STORE,
    payload: {
        serviceFullName,
        host,
    },
});

export const DELETE_SERVICE_INSTANCE_FROM_STORE =
    'DELETE_SERVICE_INSTANCE_FROM_STORE';
export const deleteServiceInstanceFromStore = (
    serviceFullName,
    instanceId,
    category
) => ({
    type: DELETE_SERVICE_INSTANCE_FROM_STORE,
    payload: {
        serviceFullName: serviceFullName,
        instanceId: instanceId,
        category: category,
    },
});
