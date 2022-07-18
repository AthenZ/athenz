import { loadingInProcess, loadingSuccess } from '../../actions/loading';
import {
    addMemberToRolesToStore,
    loadRole,
    loadRoles,
    loadRoleUsers,
} from '../../actions/roles';
import { getExpiryTime, getFullName, listToMap } from '../../utils';
import API from '../../../api';
import { roleDelimiter } from '../../config';

const getApi = (() => {
    let api;
    return () => {
        if (api) {
            return api;
        }
        api = API();
        return api;
    }
})();


const mergeUserListWithRoleListData = (roleMap, userMap) => {
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
    try {
        dispatch(loadingInProcess('getRoles'));
        const roleList = await getApi().getRoles(domainName, true);
        const userList = await getApi().getRoleMembers(domainName);

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
    } catch (error) {
        console.log('error: ', error);
    }
};

export const getRoleApiCall = async (domainName, roleName, dispatch) => {
    dispatch(loadingInProcess('getRole'));
    try {
        let role = await getApi().getRole(domainName, roleName, true, true, true);
        role.roleMembers = listToMap(role.roleMembers, 'memberName');
        role.expiry = getExpiryTime();
        dispatch(
            loadRole(role, getFullName(domainName, roleDelimiter, roleName))
        );
    } catch (e) {
        throw e;
    } finally {
        dispatch(loadingSuccess('getRole'));
    }
};
