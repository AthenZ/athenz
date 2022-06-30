import { loadingInProcess, loadingSuccess } from '../../actions/loading';
import { policyListToMap } from '../../utils';
import API from '../../../api';
import {
    addAssertionPolicyVersionToStore,
    loadPolicies,
} from '../../actions/policies';

const api = API();

export const getPoliciesApiCall = async (
    domainName,
    assertions,
    includeNonActive,
    dispatch
) => {
    dispatch(loadingInProcess('getPolicies'));
    const policyList = await api.getPolicies(
        domainName,
        assertions,
        includeNonActive
    );
    const expiry = 5;
    console.log('policyList: ', policyList);
    let policiesMap = policyListToMap(policyList);
    console.log(policiesMap);
    dispatch(loadPolicies(policiesMap, domainName, expiry));
    dispatch(loadingSuccess('getPolicies'));
};

// export const getPolicyVersionApiCall = async (domainName, policyName, version, dispatch) => {
//     dispatch(loadingInProcess('getPolicyVersion'));
//     let policyVersion = await api.getPolicyVersion(domainName, policyName, version);
//     group.groupMembers = listToMap(group.groupMembers, 'memberName');
//     group.expiry = 5;
//     dispatch(addAssertionPolicyVersionToStore(policyName, version));
//     dispatch(loadingSuccess('getPolicyVersion'));
// };
