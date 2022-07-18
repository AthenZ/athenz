import { loadMicrosegmentation } from '../actions/microsegmentation';
import {
    buildInboundOutbound,
    deleteTransportRuleApiCall,
    editMicrosegmentationHandler,
} from './utils/microsegmentation';
import { getRoles } from './roles';
import { getPolicies } from './policies';
import { loadingInProcess, loadingSuccess } from '../actions/loading';
import { selectPolicy } from '../selectors/policies';
import { getServices } from './services';

export const getInboundOutbound =
    (domainName) => async (dispatch, getState) => {
        try {
            dispatch(loadingInProcess('getInboundOutbound'));
            await dispatch(getServices(domainName));
            await dispatch(getRoles(domainName));
            await dispatch(getPolicies(domainName));
            dispatch(loadingInProcess('getInboundOutbound'));
            const inboundOutboundList = await buildInboundOutbound(
                domainName,
                getState()
            );
            dispatch(loadMicrosegmentation(inboundOutboundList, domainName, 5));
            dispatch(loadingSuccess('getInboundOutbound'));
            return Promise.resolve();
        } catch (e) {
            return Promise.reject(e);
        }
    };

export const editMicrosegmentation =
    (
        domainName,
        roleChanged,
        assertionChanged,
        assertionConditionChanged,
        data,
        _csrf
    ) =>
    async (dispatch, getState) => {
        try {
            dispatch(loadingInProcess('editMicrosegmentation'));
            await editMicrosegmentationHandler(
                domainName,
                roleChanged,
                assertionChanged,
                assertionConditionChanged,
                data,
                _csrf,
                dispatch,
                getState()
            );
            dispatch(loadingSuccess('editMicrosegmentation'));
            return Promise.resolve();
        } catch (e) {
            return Promise.reject(e);
        }
    };

export const deleteTransportRule =
    (domain, deletePolicyName, assertionId, deleteRoleName, auditRef, _csrf) =>
    async (dispatch, getState) => {
        await dispatch(getRoles(domain));
        await dispatch(getPolicies(domain));
        const policy = selectPolicy(getState(), domain, deletePolicyName);
        if (!policy) {
            //TODO - throw error
            return Promise.reject('TODO');
        }
        try {
            await deleteTransportRuleApiCall(
                domain,
                deletePolicyName,
                policy.version,
                assertionId,
                deleteRoleName,
                auditRef,
                _csrf,
                dispatch
            );
            return Promise.resolve();
        } catch (e) {
            return Promise.reject(e);
        }
    };
