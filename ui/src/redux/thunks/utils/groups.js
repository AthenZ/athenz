import { loadingInProcess, loadingSuccess } from '../../actions/loading';
import {
    addGroupToStore,
    deleteGroupFromStore,
    loadGroup,
    loadGroups,
    reviewGroup,
} from '../../actions/groups';
import API from '../../../api';
import {
    additionsToAddCollection,
    getCurrentTime,
    getExpiryTime,
    listToMap,
} from '../../utils';

const api = API();

export const deleteGroupApiCall = async (
    domainName,
    groupName,
    auditRef,
    _csrf,
    onSuccess,
    onFail,
    dispatch
) => {
    await api
        .deleteGroup(domainName, groupName, auditRef, _csrf)
        .then(() => {
            dispatch(deleteGroupFromStore(groupName, domainName));
            onSuccess(groupName);
        })
        .catch((err) => {
            onFail(err);
        });
};

// need to add to the response the group members data
export const addGroupApiCall = async (
    domainName,
    groupName,
    group,
    auditRef,
    _csrf,
    onSuccess,
    onFail,
    dispatch
) => {
    api.addGroup(domainName, groupName, group, auditRef, _csrf)
        .then((response) => {
            additionsToAddCollection(
                group,
                domainName,
                ':group.',
                'groupMembers',
                'memberName'
            );
            dispatch(addGroupToStore(groupName, group));
            onSuccess();
        })
        .catch((err) => {
            onFail(err);
        });
};

export const reviewGroupApiCall = async (
    domainName,
    groupName,
    group,
    justification,
    _csrf,
    onSuccess,
    onFail,
    dispatch
) => {
    api.reviewGroup(domainName, groupName, group, justification, _csrf)
        .then(() => {
            console.log('reviewGroupApiCall', group);
            group.groupMembers = group.groupMembers.filter(
                (member) => member.active !== false
            );
            dispatch(reviewGroup(groupName, group.groupMembers));
            onSuccess();
        })
        .catch((err) => {
            onFail(err);
        });
};

export const getGroupsApiCall = async (domainName, dispatch) => {
    dispatch(loadingInProcess('getGroups'));
    console.log('getGroupsApiCall', domainName);
    const groupList = await api.getGroups(domainName, true);
    const expiry = getExpiryTime();
    let groupsMap = listToMap(groupList, 'name', ':group.');
    console.log('getGroupsApiCall', groupsMap);
    dispatch(loadGroups(groupsMap, domainName, expiry));
    dispatch(loadingSuccess('getGroups'));
};

export const getGroupApiCall = async (domainName, groupName, dispatch) => {
    dispatch(loadingInProcess('getGroup'));
    let group = await api.getGroup(domainName, groupName, true, true);
    group.groupMembers = listToMap(group.groupMembers, 'memberName');
    group.expiry = getExpiryTime();
    dispatch(loadGroup(group, groupName));
    dispatch(loadingSuccess('getGroup'));
};
