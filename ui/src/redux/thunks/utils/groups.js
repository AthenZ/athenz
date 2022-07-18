import { loadingInProcess, loadingSuccess } from '../../actions/loading';
import { loadGroup, loadGroups } from '../../actions/groups';
import API from '../../../api';
import { getExpiryTime, getFullName, listToMap } from '../../utils';
import { groupDelimiter } from '../../config';

const api = API();

export const getGroupsApiCall = async (domainName, dispatch) => {
    dispatch(loadingInProcess('getGroups'));
    const groupList = await api.getGroups(domainName, true);
    const expiry = getExpiryTime();
    groupList.forEach((group) => {
        group.expiry = expiry;
        group.groupMembers = listToMap(group.groupMembers, 'memberName');
    });
    let groupsMap = listToMap(groupList, 'name');
    dispatch(loadGroups(groupsMap, domainName, expiry));
    dispatch(loadingSuccess('getGroups'));
};

export const getGroupApiCall = async (domainName, groupName, dispatch) => {
    dispatch(loadingInProcess('getGroup'));
    let group = await api.getGroup(domainName, groupName, true, true);
    group.groupMembers = listToMap(group.groupMembers, 'memberName');
    group.expiry = getExpiryTime();
    dispatch(
        loadGroup(group, getFullName(domainName, groupDelimiter, groupName))
    );
    dispatch(loadingSuccess('getGroup'));
};
