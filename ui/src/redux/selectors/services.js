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

import { mapToList } from '../utils';
import { getFullName } from '../utils';
import { serviceDelimiter } from '../config';

export const getSafe = (fn, defaultValue) => {
    try {
        return fn();
    } catch (err) {
        return defaultValue;
    }
};

export const thunkSelectServices = (state) => {
    return state.services.services ? state.services.services : [];
};

export const thunkSelectService = (state, domainName, serviceName) => {
    return selectService(state, domainName, serviceName);
};

export const selectServices = (state) => {
    return state.services.services ? mapToList(state.services.services) : [];
};

export const selectService = (state, domainName, serviceName) => {
    return getSafe(
        () =>
            state.services.services[
                getFullName(domainName, serviceDelimiter, serviceName)
            ],
        {}
    );
};

export const selectServiceTags = (state, domainName, serviceName) => {
    return getSafe(
        () =>
            state.services.services[
                getFullName(domainName, serviceDelimiter, serviceName)
            ].tags,
        {}
    );
};

export const selectServicePublicKeys = (state, domainName, serviceName) => {
    return mapToList(
        getSafe(
            () =>
                state.services.services[
                    getFullName(domainName, serviceDelimiter, serviceName)
                ].publicKeys,
            {}
        )
    );
};

export const selectServiceDescription = (state, domainName, serviceName) => {
    return getSafe(
        () =>
            state.services.services[
                getFullName(domainName, serviceDelimiter, serviceName)
            ].description,
        null
    );
};

export const selectProvider = (state, domainName, serviceName) => {
    return getSafe(
        () =>
            state.services.services[
                getFullName(domainName, serviceDelimiter, serviceName)
            ].provider,
        {}
    );
};
export const selectAllProviders = (state) => {
    return state.services && state.services.allProviders
        ? state.services.allProviders
        : [];
};

export const selectDynamicServiceHeaderDetails = (
    state,
    domainName,
    serviceName
) => {
    return getSafe(
        () =>
            state.services.services[
                getFullName(domainName, serviceDelimiter, serviceName)
            ].serviceHeaderDetails.dynamic,
        {}
    );
};

export const selectStaticServiceHeaderDetails = (
    state,
    domainName,
    serviceName
) => {
    return getSafe(
        () =>
            state.services.services[
                getFullName(domainName, serviceDelimiter, serviceName)
            ].serviceHeaderDetails.static,
        {}
    );
};

export const selectInstancesWorkLoadMeta = (
    state,
    domainName,
    serviceName,
    category
) => {
    let currService = selectService(state, domainName, serviceName);
    if (category === 'dynamic') {
        return currService.dynamicInstances
            ? currService.dynamicInstances.workLoadMeta
            : {};
    } else {
        return currService.staticInstances
            ? currService.staticInstances.workLoadMeta
            : {};
    }
};

export const selectInstancesWorkLoadData = (
    state,
    domainName,
    serviceName,
    category
) => {
    let currService = selectService(state, domainName, serviceName);
    if (category === 'dynamic') {
        return currService && currService.dynamicInstances
            ? currService.dynamicInstances.workLoadData
            : [];
    } else {
        return currService && currService.staticInstances
            ? currService.staticInstances.workLoadData
            : [];
    }
};
