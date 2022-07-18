import { mapToList } from '../utils';
import { getFullName } from '../utils';
import { serviceDelimiter } from '../config';

export const thunkSelectServices = (state) => {
    return state.services.services ? state.services.services : [];
};

export const thunkSelectService = (state, domainName, serviceName) => {
    return selectService(state, domainName, serviceName);
};

export const thunkSelectProvider = (state, domainName, serviceName) => {
    return selectProvider(state, domainName, serviceName);
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
    console.log(
        'in selectServicePublicKeys',
        domainName,
        serviceName,
        state.services.services
    );
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
export const selectAllProviders = (state, domainName, serviceName) => {
    return state.services.services &&
        state.services.services[
            getFullName(domainName, serviceDelimiter, serviceName)
        ] &&
        state.services.services[
            getFullName(domainName, serviceDelimiter, serviceName)
        ].allProviders
        ? state.services.services[
              getFullName(domainName, serviceDelimiter, serviceName)
          ].allProviders
        : [];
};
