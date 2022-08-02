import { mapToList } from '../utils';
import { getFullName } from '../utils';
import { serviceDelimiter } from '../config';

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
    return state.services.services &&
        state.services.services[
            getFullName(domainName, serviceDelimiter, serviceName)
        ]
        ? state.services.services[
              getFullName(domainName, serviceDelimiter, serviceName)
          ]
        : {};
};

export const selectServicePublicKeys = (state, domainName, serviceName) => {
    return state.services.services &&
        state.services.services[
            getFullName(domainName, serviceDelimiter, serviceName)
        ] &&
        state.services.services[
            getFullName(domainName, serviceDelimiter, serviceName)
        ].publicKeys
        ? mapToList(
              state.services.services[
                  getFullName(domainName, serviceDelimiter, serviceName)
              ].publicKeys
          )
        : [];
};

export const selectServiceDescription = (state, domainName, serviceName) => {
    return state.services.services &&
        state.services.services[
            getFullName(domainName, serviceDelimiter, serviceName)
        ] &&
        state.services.services[
            getFullName(domainName, serviceDelimiter, serviceName)
        ].description
        ? state.services.services[
              getFullName(domainName, serviceDelimiter, serviceName)
          ].description
        : null;
};

export const selectProvider = (state, domainName, serviceName) => {
    return state.services.services &&
        state.services.services[
            getFullName(domainName, serviceDelimiter, serviceName)
        ] &&
        state.services.services[
            getFullName(domainName, serviceDelimiter, serviceName)
        ].provider
        ? state.services.services[
              getFullName(domainName, serviceDelimiter, serviceName)
          ].provider
        : {};
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
    return state.services.services &&
        state.services.services[
            getFullName(domainName, serviceDelimiter, serviceName)
        ] &&
        state.services.services[
            getFullName(domainName, serviceDelimiter, serviceName)
        ].serviceHeaderDetails
        ? state.services.services[
              getFullName(domainName, serviceDelimiter, serviceName)
          ].serviceHeaderDetails.dynamic
        : {};
};

export const selectStaticServiceHeaderDetails = (
    state,
    domainName,
    serviceName
) => {
    return state.services.services &&
        state.services.services[
            getFullName(domainName, serviceDelimiter, serviceName)
        ] &&
        state.services.services[
            getFullName(domainName, serviceDelimiter, serviceName)
        ].serviceHeaderDetails
        ? state.services.services[
              getFullName(domainName, serviceDelimiter, serviceName)
          ].serviceHeaderDetails.static
        : {};
};

export const selectDynamicInstanceDetails = (
    state,
    domainName,
    serviceName
) => {
    return state.services.services &&
        state.services.services[
            getFullName(domainName, serviceDelimiter, serviceName)
        ] &&
        state.services.services[
            getFullName(domainName, serviceDelimiter, serviceName)
        ].instanceDetails
        ? state.services.services[
              getFullName(domainName, serviceDelimiter, serviceName)
          ].dynamicInstances
        : {};
};
