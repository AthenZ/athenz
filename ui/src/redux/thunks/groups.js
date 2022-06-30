import {
    loadGroups,
    loadGroupRoleMembers,
    returnGroups,
    returnRoleMembers,
} from '../actions/groups';
import API from '../../api';
import { loadingInProcess, loadingSuccess } from '../actions/loading';
import { storeGroups } from '../actions/domains';
import {
    addGroupApiCall,
    deleteGroupApiCall,
    getGroupApiCall,
    getGroupsApiCall,
    reviewGroupApiCall,
} from './utils/groups';
import {
    thunkSelectGroup,
    thunkSelectGroupRoleMembers,
    thunkSelectGroups,
} from '../selectors/group';

const api = API();

//TODO test it again the new API
export const addGroup =
    (groupName, auditRef, group, _csrf, onSuccess, onFail) =>
    async (dispatch, getState) => {
        let domainName = getState().groups.domainName;
        await dispatch(getGroups(domainName));
        let groupsMap = thunkSelectGroups(getState());
        if (groupName in groupsMap) {
            onFail({
                body: { message: 'Group already exists' },
                statusCode: 409,
            });
        } else {
            await addGroupApiCall(
                domainName,
                groupName,
                group,
                auditRef,
                _csrf,
                onSuccess,
                onFail,
                dispatch
            );
        }
    };

export const deleteGroup =
    (groupName, auditRef, _csrf, onSuccess, onFail) =>
    async (dispatch, getState) => {
        let domainName = getState().groups.domainName;
        await dispatch(getGroups(domainName));
        let groupsMap = thunkSelectGroups(getState());
        if (!(groupName in groupsMap)) {
            onFail({
                body: { message: 'Group doesnt exists' },
                statusCode: 409,
            });
        } else {
            await deleteGroupApiCall(
                domainName,
                groupName,
                auditRef,
                _csrf,
                onSuccess,
                onFail,
                dispatch
            );
        }
    };

export const reviewGroup =
    (groupName, group, justification, _csrf, onSuccess, onFail) =>
    async (dispatch, getState) => {
        let domainName = getState().groups.domainName;
        await dispatch(getGroup(domainName, groupName));
        await reviewGroupApiCall(
            domainName,
            groupName,
            group,
            justification,
            _csrf,
            onSuccess,
            onFail,
            dispatch
        );
    };

// i think it is a domain level function need to check
export const getDomainRoleMembers =
    (domainName, groupName) => async (dispatch, getState) => {
        await dispatch(getGroups(domainName));
        let currRoleMembers = thunkSelectGroupRoleMembers(
            getState(),
            groupName
        );
        if (
            currRoleMembers &&
            currRoleMembers.memberName === domainName + ':group.' + groupName
        ) {
            dispatch(returnRoleMembers());
        } else {
            dispatch(loadingInProcess('getDomainRoleMembers'));
            currRoleMembers = await api.getDomainRoleMembers(
                domainName + ':group.' + groupName
            );
            dispatch(loadGroupRoleMembers(currRoleMembers));
            // dispatch(storeGroups(getState().groups));
            dispatch(loadingSuccess('getDomainRoleMembers'));
        }
    };

export const getGroup =
    (domainName, groupName) => async (dispatch, getState) => {
        await dispatch(getGroups(domainName));
        let currGroup = thunkSelectGroup(getState(), groupName);
        // we want to check if the groupMembers are exits but if i add a group the members data is not the same as the data returned from the backend
        if (currGroup.auditLog && currGroup.expiry > 0) {
        } else {
            await getGroupApiCall(domainName, groupName, dispatch);
        }
    };

export const getGroups = (domainName) => async (dispatch, getState) => {
    let groups = getState().groups;
    if (groups.expiry) {
        if (groups.domainName !== domainName) {
            dispatch(storeGroups(groups));
            if (
                getState().domains[domainName] &&
                getState().domains[domainName].groups &&
                getState().domains[domainName].groups.expiry > 0
            ) {
                dispatch(
                    loadGroups(
                        getState().domains[domainName].groups,
                        domainName,
                        getState().domains[domainName].groups.expiry
                    )
                );
            } else {
                await getGroupsApiCall(domainName, dispatch);
            }
        } else if (groups.expiry <= 0) {
            await getGroupsApiCall(domainName, dispatch);
        } else {
            dispatch(returnGroups());
        }
    } else {
        await getGroupsApiCall(domainName, dispatch);
    }
};
