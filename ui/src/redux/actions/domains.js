export const LOAD_USER_DOMAINS_LIST = 'LOAD_USER_DOMAINS_LIST';
export const loadUserDomainList = (domainsList) => ({
    type: LOAD_USER_DOMAINS_LIST,
    payload: { domainsList: domainsList },
});

export const RETURN_DOMAIN_LIST = 'RETURN_DOMAIN_LIST';
export const returnDomainList = (domainList) => ({
    type: RETURN_DOMAIN_LIST,
    payload: { domainsList: domainList },
});

export const STORE_DOMAIN_DATA = 'STORE_DOMAIN_DATA';
export const storeDomainData = (domainData) => ({
    type: STORE_DOMAIN_DATA,
    payload: { domainData: domainData },
});

export const STORE_ROLES = 'STORE_ROLES';
export const storeRoles = (rolesData) => ({
    type: STORE_ROLES,
    payload: { rolesData: rolesData },
});

export const STORE_GROUPS = 'STORE_GROUPS';
export const storeGroups = (groupsData) => ({
    type: STORE_GROUPS,
    payload: { groupsData: groupsData },
});

export const STORE_SERVICES = 'STORE_SERVICES';
export const storeServices = (serviceData) => ({
    type: STORE_SERVICES,
    payload: { serviceData: serviceData },
});

export const STORE_POLICIES = 'STORE_POLICIES';
export const storePolicies = (policiesData) => ({
    type: STORE_POLICIES,
    payload: { policiesData: policiesData },
});

export const STORE_TEMPLATES = 'STORE_TEMPLATES';
export const storeTemplates = (templatesData) => ({
    type: STORE_TEMPLATES,
    payload: { templatesData: templatesData },
});

export const STORE_HISTORY= 'STORE_HISTORY';
export const storeHistory = (historyData) => ({
    type: STORE_HISTORY,
    payload: { historyData: historyData },
});

export const STORE_SERVICE_DEPENDENCIES = 'STORE_SERVICE_DEPENDENCIES';
export const storeServiceDependencies = (serviceDependenciesData) => ({
    type: STORE_SERVICE_DEPENDENCIES,
    payload: { serviceDependenciesData: serviceDependenciesData },
});
