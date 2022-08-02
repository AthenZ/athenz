import { loadingInProcess, loadingSuccess } from '../../actions/loading';
import { loadRole, loadRoles } from '../../actions/roles';
import { getExpiryTime, getFullName, listToMap } from '../../utils';
import API from '../../../api';
import { roleDelimiter } from '../../config';
import { thunkSelectRoleMembers } from '../../selectors/roles';

export const mergeUserListWithRoleListData = (roleMap, userMap) => {
    for (const [memberName, member] of Object.entries(userMap)) {
        for (const [roleName, role] of Object.entries(roleMap)) {
            if (role.roleMembers[memberName]) {
                role.roleMembers[memberName].memberFullName =
                    member.memberFullName;
            }
        }
    }
    return roleMap;
};

export const getRolesApiCall = async (domainName, dispatch) => {
    dispatch(loadingInProcess('getRoles'));
    // the role page has 2 tabs role and users and for making those 2 pages using a single source of truth
    // we combine the data from the 2 api calls into one object holds in the store
    const roleList = await API().getRoles(domainName, true);
    const userList = await API().getRoleMembers(domainName);
    const expiry = getExpiryTime();
    roleList.forEach((role) => {
        role.roleMembers = listToMap(role.roleMembers, 'memberName');
    });
    let rolesMap = listToMap(roleList, 'name');
    rolesMap = mergeUserListWithRoleListData(
        rolesMap,
        listToMap(userList.members, 'memberName')
    );
    dispatch(loadRoles(rolesMap, domainName, expiry));
    dispatch(loadingSuccess('getRoles'));
};

export const getRoleApiCall = async (domainName, roleName, dispatch) => {
    dispatch(loadingInProcess('getRole'));
    try {
        let role = await API().getRole(domainName, roleName, true, false, true);
        role.roleMembers = listToMap(role.roleMembers, 'memberName');
        dispatch(
            loadRole(role, getFullName(domainName, roleDelimiter, roleName))
        );
    } catch (e) {
        throw e;
    } finally {
        dispatch(loadingSuccess('getRole'));
    }
};

export const checkIfMemberInAllRoles = (
    domainName,
    state,
    roleList,
    memberName
) => {
    let checkedMemberInAllRoles = true;
    for (let roleName of roleList) {
        let roleMembers = thunkSelectRoleMembers(state, domainName, roleName);
        if (!(memberName in roleMembers)) {
            checkedMemberInAllRoles = false;
            break;
        }
    }
    return checkedMemberInAllRoles;
};
