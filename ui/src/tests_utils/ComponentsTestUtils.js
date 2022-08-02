import { render } from '@testing-library/react';
import { Provider } from 'react-redux';
import { initStore } from '../redux/store';
import { getExpiryTime } from '../redux/utils';

export const renderWithRedux = (component, initialState = {}) => {
    return render(
        <Provider store={initStore(initialState)}>{component}</Provider>
    );
};

export const buildUserForState = (user) => {
    return {
        expiry: getExpiryTime(),
        user,
    };
};

export const getStateWithUser = (user, initialState = {}) => {
    return { ...initialState, user };
};

export const buildDomainDataForState = (domainData, domainName = 'dom') => {
    return {
        domainName,
        expiry: getExpiryTime(),
        domainData,
    };
};

export const getStateWithDomainData = (domainData, initialState = {}) => {
    return { ...initialState, domainData: domainData };
};

export const getStateWithRoles = (roles, initialState = {}) => {
    return { ...initialState, roles };
};

export const buildRolesForState = (roles, domainName = 'dom') => {
    return {
        domainName,
        expiry: getExpiryTime(),
        roles,
    };
};

export const buildPoliciesForState = (policies, domainName = 'dom') => {
    return {
        domainName,
        expiry: getExpiryTime(),
        policies,
    };
};

export const getStateWithPolicies = (policies, initialState = {}) => {
    return { ...initialState, policies };
};

export const buildServicesForState = (
    services,
    domainName = 'dom',
    allProviders = []
) => {
    return {
        domainName,
        expiry: getExpiryTime(),
        services,
        allProviders,
    };
};

export const getStateWithServices = (services, initialState = {}) => {
    return { ...initialState, services };
};

export const buildMicrosegmentationForState = (
    inboundOutboundList,
    domainName = 'dom'
) => {
    return {
        domainName,
        expiry: getExpiryTime(),
        inboundOutboundList,
    };
};

export const getStateWithMicrosegmentation = (
    microsegmentation,
    initialState = {}
) => {
    return { ...initialState, microsegmentation };
};

export const buildGroupsForState = (groups, domainName = 'dom') => {
    return {
        domainName,
        expiry: getExpiryTime(),
        groups,
    };
};

export const getStateWithGroups = (groups, initialState = {}) => {
    return { ...initialState, groups };
};

export const buildServiceDependencies = (
    serviceDependencies,
    domainName = 'dom'
) => {
    return {
        domainName,
        expiry: getExpiryTime(),
        serviceDependencies,
    };
};

export const getStateWithServiceDependencies = (
    serviceDependencies,
    initialState = {}
) => {
    return { ...initialState, serviceDependencies: serviceDependencies };
};

export const mockRolesApiCalls = () => {
    return {
        getRoles: jest.fn().mockReturnValue(
            new Promise((resolve, reject) => {
                resolve([]);
            })
        ),
        getRoleMembers: jest.fn().mockReturnValue(
            new Promise((resolve, reject) => {
                resolve({});
            })
        ),
    };
};

export const mockAllDomainDataApiCalls = (domainDetails, headerDetails) => {
    return {
        getDomain: jest.fn().mockReturnValue(
            new Promise((resolve, reject) => {
                resolve(domainDetails || {});
            })
        ),
        isAWSTemplateApplied: jest.fn().mockReturnValue(
            new Promise((resolve, reject) => {
                resolve('');
            })
        ),
        getHeaderDetails: jest.fn().mockReturnValue(
            new Promise((resolve, reject) => {
                resolve(headerDetails || {});
            })
        ),
        getPendingDomainMembersListByDomain: jest.fn().mockReturnValue(
            new Promise((resolve, reject) => {
                resolve([]);
            })
        ),
        getFeatureFlag: jest.fn().mockReturnValue(
            new Promise((resolve, reject) => {
                resolve('');
            })
        ),
        getMeta: jest.fn().mockReturnValue(
            new Promise((resolve, reject) => {
                resolve([]);
            })
        ),
        getAuthorityAttributes: jest.fn().mockReturnValue(
            new Promise((resolve, reject) => {
                resolve({});
            })
        ),
    };
};
