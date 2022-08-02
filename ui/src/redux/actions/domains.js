export const LOAD_USER_DOMAINS_LIST = 'LOAD_USER_DOMAINS_LIST';
export const loadUserDomainList = (domainsList) => ({
    type: LOAD_USER_DOMAINS_LIST,
    payload: { domainsList: domainsList },
});

export const RETURN_DOMAIN_LIST = 'RETURN_DOMAIN_LIST';
export const returnDomainList = () => ({
    type: RETURN_DOMAIN_LIST,
});

export const LOAD_BUSINESS_SERVICES_ALL = 'LOAD_BUSINESS_SERVICES_ALL';
export const loadBusinessServicesAll = (businessServicesAll) => ({
    type: LOAD_BUSINESS_SERVICES_ALL,
    payload: { businessServicesAll },
});

export const RETURN_BUSINESS_SERVICES_ALL = 'RETURN_BUSINESS_SERVICES_ALL';
export const returnBusinessServicesAll = () => ({
    type: RETURN_BUSINESS_SERVICES_ALL,
});

export const ADD_DOMAIN_TO_USER_DOMAINS_LIST =
    'ADD_DOMAIN_TO_USER_DOMAINS_LIST';
export const addDomainToUserDomainsList = (domainName) => ({
    type: ADD_DOMAIN_TO_USER_DOMAINS_LIST,
    payload: { name: domainName, adminDomain: true },
});

export const DELETE_DOMAIN_FROM_USER_DOMAINS_LIST =
    'DELETE_DOMAIN_FROM_USER_DOMAINS_LIST';
export const deleteDomainFromUserDomainList = (subDomain) => ({
    type: DELETE_DOMAIN_FROM_USER_DOMAINS_LIST,
    payload: { subDomain },
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
export const storeServices = (servicesData) => ({
    type: STORE_SERVICES,
    payload: { servicesData: servicesData },
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

export const STORE_HISTORY = 'STORE_HISTORY';
export const storeHistory = (historyData) => ({
    type: STORE_HISTORY,
    payload: { historyData: historyData },
});

export const STORE_SERVICE_DEPENDENCIES = 'STORE_SERVICE_DEPENDENCIES';
export const storeServiceDependencies = (serviceDependenciesData) => ({
    type: STORE_SERVICE_DEPENDENCIES,
    payload: { serviceDependenciesData: serviceDependenciesData },
});

export const STORE_MICROSEGMENTATION = 'STORE_MICROSEGMENTATION';
export const storeMicrosegmentation = (microsegmentationData) => ({
    type: STORE_MICROSEGMENTATION,
    payload: { microsegmentationData: microsegmentationData },
});

export const LOAD_ALL_DOMAINS_LIST = 'LOAD_ALL_DOMAINS_LIST';
export const loadAllDomainsList = (allDomainsList) => ({
    type: LOAD_ALL_DOMAINS_LIST,
    payload: { allDomainsList },
});

export const LOAD_PENDING_DOMAIN_MEMBERS_LIST =
    'LOAD_PENDING_DOMAIN_MEMBERS_LIST';
export const loadPendingDomainMembersList = (
    pendingDomainMembersList,
    domainName
) => ({
    type: LOAD_PENDING_DOMAIN_MEMBERS_LIST,
    payload: { pendingDomainMembersList, domainName },
});

export const PROCESS_PENDING_MEMBERS_TO_STORE =
    'PROCESS_PENDING_MEMBERS_TO_STORE';
export const processPendingMembersToStore = (roleName, member) => ({
    type: PROCESS_PENDING_MEMBERS_TO_STORE,
    payload: { member, roleName },
});
