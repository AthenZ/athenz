import {
    deleteInboundFromStore,
    deleteOutboundFromStore,
    loadMicrosegmentation,
} from '../actions/microsegmentation';
import {
    buildInboundOutbound,
    editMicrosegmentationHandler,
    getCategoryFromPolicyName,
} from './utils/microsegmentation';
import { getRoles } from './roles';
import { getPolicies } from './policies';
import { loadingInProcess, loadingSuccess } from '../actions/loading';
import { selectPolicyThunk } from '../selectors/policies';
import { getServices } from './services';
import API from '../../api';
import { deleteAssertionPolicyVersionFromStore } from '../actions/policies';
import { getPolicyFullName } from './utils/policies';
import { deleteRoleFromStore } from '../actions/roles';
import { buildErrorForDoesntExistCase, getFullName } from '../utils';
import { roleDelimiter } from '../config';

export const getInboundOutbound =
    (domainName) => async (dispatch, getState) => {
        try {
            dispatch(loadingInProcess('getInboundOutbound'));
            await dispatch(getServices(domainName));
            await dispatch(getRoles(domainName));
            await dispatch(getPolicies(domainName));
            const inboundOutboundList = buildInboundOutbound(
                domainName,
                getState()
            );
            dispatch(loadMicrosegmentation(inboundOutboundList, domainName));
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
        const policy = selectPolicyThunk(getState(), domain, deletePolicyName);
        if (!policy) {
            return Promise.reject(
                buildErrorForDoesntExistCase('Policy', deletePolicyName)
            );
        }
        try {
            await API().deleteTransportRule(
                domain,
                deletePolicyName,
                assertionId,
                deleteRoleName,
                auditRef,
                _csrf
            );
            dispatch(
                deleteAssertionPolicyVersionFromStore(
                    getPolicyFullName(domain, deletePolicyName),
                    policy.version,
                    assertionId
                )
            );
            dispatch(
                deleteRoleFromStore(
                    getFullName(domain, roleDelimiter, deleteRoleName)
                )
            );
            switch (getCategoryFromPolicyName(deletePolicyName)) {
                case 'inbound':
                    dispatch(deleteInboundFromStore(assertionId));
                    break;
                case 'outbound':
                    dispatch(deleteOutboundFromStore(assertionId));
                    break;
                default:
            }
            return Promise.resolve();
        } catch (e) {
            return Promise.reject(e);
        }
    };
