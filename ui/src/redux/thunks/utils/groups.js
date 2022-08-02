import { loadingInProcess, loadingSuccess } from '../../actions/loading';
import { loadGroup, loadGroups } from '../../actions/groups';
import API from '../../../api';
import { getExpiryTime, getFullName, listToMap } from '../../utils';
import { groupDelimiter } from '../../config';

export const getGroupsApiCall = async (domainName, dispatch) => {
    dispatch(loadingInProcess('getGroups'));
    const groupList = await API().getGroups(domainName, true);
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
    let group = await API().getGroup(domainName, groupName, true, true);
    group.groupMembers = listToMap(group.groupMembers, 'memberName');
    dispatch(
        loadGroup(group, getFullName(domainName, groupDelimiter, groupName))
    );
    dispatch(loadingSuccess('getGroup'));
};
