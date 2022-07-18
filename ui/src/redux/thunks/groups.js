import {
    addGroupToStore,
    deleteGroupFromStore,
    loadGroupRoleMembers,
    loadGroups,
    returnGroups,
    returnRoleMembers,
    reviewGroupToStore,
} from '../actions/groups';
import API from '../../api';
import { loadingInProcess, loadingSuccess } from '../actions/loading';
import { storeGroups } from '../actions/domains';
import { getGroupApiCall, getGroupsApiCall } from './utils/groups';
import {
    thunkSelectGroup,
    thunkSelectGroupRoleMembers,
    thunkSelectGroups,
} from '../selectors/group';
import {
    getCurrentTime,
    getExpiryTime,
    getFullName,
    isExpired,
    listToMap,
} from '../utils';
import { groupDelimiter, memberNameKey } from '../config';

const api = API();

//TODO test it again the new API
export const addGroup =
    (groupName, auditRef, group, _csrf) => async (dispatch, getState) => {
        let domainName = getState().groups.domainName;
        await dispatch(getGroups(domainName));
        let groupsMap = thunkSelectGroups(getState());
        if (getFullName(domainName, groupDelimiter, groupName) in groupsMap) {
            return Promise.reject({
                body: { message: `Group ${groupName} already exists` },
                statusCode: 409,
            });
        } else {
            try {
                await api.addGroup(
                    domainName,
                    groupName,
                    group,
                    auditRef,
                    _csrf
                );
                group.expiry = getExpiryTime();
                group.modified = getCurrentTime();
                group.name = getFullName(domainName, groupDelimiter, groupName);
                group.groupMembers = listToMap(
                    group.groupMembers,
                    memberNameKey
                );
                dispatch(
                    addGroupToStore(
                        getFullName(domainName, groupDelimiter, groupName),
                        group
                    )
                );
                return Promise.resolve();
            } catch (err) {
                return Promise.reject(err);
            }
        }
    };

export const deleteGroup =
    (groupName, auditRef, _csrf) => async (dispatch, getState) => {
        let domainName = getState().groups.domainName;
        await dispatch(getGroups(domainName));
        let groupsMap = thunkSelectGroups(getState());
        if (
            !(getFullName(domainName, groupDelimiter, groupName) in groupsMap)
        ) {
            return Promise.reject({
                body: { message: `Group ${groupName} doesnt exists` },
                statusCode: 404,
            });
        } else {
            try {
                await api.deleteGroup(domainName, groupName, auditRef, _csrf);
                dispatch(
                    deleteGroupFromStore(
                        getFullName(domainName, groupDelimiter, groupName),
                        domainName
                    )
                );
                return Promise.resolve();
            } catch (err) {
                return Promise.reject(err);
            }
        }
    };

export const reviewGroup =
    (groupName, group, justification, _csrf) => async (dispatch, getState) => {
        let domainName = getState().groups.domainName;
        await dispatch(getGroup(domainName, groupName));
        try {
            await api.reviewGroup(
                domainName,
                groupName,
                group,
                justification,
                _csrf
            );
            group.groupMembers = group.groupMembers.filter(
                (member) => member.active !== false
            );
            dispatch(
                reviewGroupToStore(
                    getFullName(domainName, groupDelimiter, groupName),
                    group.groupMembers
                )
            );
            return Promise.resolve();
        } catch (err) {
            return Promise.reject(err);
        }
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
        let currGroup = thunkSelectGroup(getState(), domainName, groupName);
        // the only time we want to load the group is if it has no auditLog or if it is expired
        if (currGroup.auditLog && isExpired(currGroup.expiry)) {
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
                !isExpired(getState().domains[domainName].groups.expiry)
            ) {
                dispatch(
                    loadGroups(
                        getState().domains[domainName].groups.groups,
                        domainName,
                        getState().domains[domainName].groups.expiry
                    )
                );
            } else {
                await getGroupsApiCall(domainName, dispatch);
            }
        } else if (isExpired(groups.expiry)) {
            await getGroupsApiCall(domainName, dispatch);
        } else {
            dispatch(returnGroups());
        }
    } else {
        await getGroupsApiCall(domainName, dispatch);
    }
};
