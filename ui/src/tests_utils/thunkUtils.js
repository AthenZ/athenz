import {
    addAssertionPolicyVersionToStore,
    deleteAssertionPolicyVersionFromStore,
    loadPolicies,
} from '../redux/actions/policies';
import { getExpiryTime } from '../redux/utils';
import { storeDomainData, storePolicies } from '../redux/actions/domains';
import { loadDomainData } from '../redux/actions/domain-data';

export const getLoadDomainDataAction = (domainName, domainData) => {
    return loadDomainData(domainData, domainName, getExpiryTime());
};

export const getStoreDomainDataAction = (domainData) => {
    return storeDomainData(domainData);
};

export const getLoadPoliciesAction = (domainName, policies = {}) => {
    return loadPolicies(policies, domainName, getExpiryTime());
};

export const getStorePoliciesAction = (policiesData) => {
    return storePolicies(policiesData);
};

export const getDeleteAssertionPolicyVersionAction = (policyName, version, assertionId) => {
    return deleteAssertionPolicyVersionFromStore(policyName, version, assertionId);
};

export const getAddAssertionPolicyVersionAction = (policyName, version, newAssertion) => {
    return addAssertionPolicyVersionToStore(
        policyName, version, newAssertion
    )
};
