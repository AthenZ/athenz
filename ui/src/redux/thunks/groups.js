import {
    addGroupToStore,
    deleteGroupFromStore,
    loadGroupRoleMembers,
    loadGroups,
    returnGroups,
    reviewGroupToStore,
} from '../actions/groups';
import API from '../../api';
import { loadingInProcess, loadingSuccess } from '../actions/loading';
import { storeGroups } from '../actions/domains';
import { getGroupApiCall, getGroupsApiCall } from './utils/groups';
import { thunkSelectGroup, thunkSelectGroups } from '../selectors/group';
import {
    buildErrorForDoesntExistCase,
    buildErrorForDuplicateCase,
    getCurrentTime,
    getExpiryTime,
    getFullName,
    isExpired,
    listToMap,
} from '../utils';
import { groupDelimiter, memberNameKey } from '../config';

// TODO roy - make the api call return the member with approve field
export const addGroup =
    (groupName, auditRef, group, _csrf) => async (dispatch, getState) => {
        let domainName = getState().groups.domainName;
        await dispatch(getGroups(domainName));
        let groupsMap = thunkSelectGroups(getState());
        if (getFullName(domainName, groupDelimiter, groupName) in groupsMap) {
            return Promise.reject(
                buildErrorForDuplicateCase('Group', groupName)
            );
        } else {
            try {
                await API().addGroup(
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
            return Promise.reject(
                buildErrorForDoesntExistCase('Group', groupName)
            );
        } else {
            try {
                await API().deleteGroup(domainName, groupName, auditRef, _csrf);
                dispatch(
                    deleteGroupFromStore(
                        getFullName(domainName, groupDelimiter, groupName)
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
            await API().reviewGroup(
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

export const getDomainRoleMembers =
    (domainName, groupName) => async (dispatch, getState) => {
        await dispatch(getGroups(domainName));
        dispatch(loadingInProcess('getDomainRoleMembers'));
        let currRoleMembers = await API().getDomainRoleMembers(
            getFullName(domainName, groupDelimiter, groupName)
        );
        dispatch(
            loadGroupRoleMembers(
                getFullName(domainName, groupDelimiter, groupName),
                currRoleMembers
            )
        );
        dispatch(loadingSuccess('getDomainRoleMembers'));
    };

export const getGroup =
    (domainName, groupName) => async (dispatch, getState) => {
        await dispatch(getGroups(domainName));
        let group = thunkSelectGroup(getState(), domainName, groupName);
        if (group.auditLog) {
            dispatch(returnGroups());
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
