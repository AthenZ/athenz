import { loadingInProcess, loadingSuccess } from '../../actions/loading';
import {
    addRoleToStore,
    deleteRoleFromStore,
    loadRole,
    loadRoles,
    reviewRole,
} from '../../actions/roles';
import {
    additionsToAddCollection,
    getCurrentTime,
    getExpiryTime,
    listToMap,
} from '../../utils';
import API from '../../../api';
import DateUtils from '../../../components/utils/DateUtils';

const api = API();

export const getRolesApiCall = async (domainName, dispatch) => {
    dispatch(loadingInProcess('getRoles'));
    const roleList = await api.getRoles(domainName, true);
    const expiry = getExpiryTime();
    let rolesMap = listToMap(roleList, 'name', ':role.');
    dispatch(loadRoles(rolesMap, domainName, expiry));
    dispatch(loadingSuccess('getRoles'));
};

export const getRoleApiCall = async (domainName, roleName, dispatch) => {
    dispatch(loadingInProcess('getRole'));
    let role = await api.getRole(domainName, roleName, true, true, true);
    console.log('in getRoleApiCall the role are: ', role);
    role.roleMembers = listToMap(role.roleMembers, 'memberName');
    role.expiry = getExpiryTime();
    dispatch(loadRole(role, roleName));
    dispatch(loadingSuccess('getRole'));
};

export const addRoleApiCall = async (
    domainName,
    roleName,
    role,
    auditRef,
    _csrf,
    dispatch,
    onSuccess,
    onFail
) => {
    api.addRole(domainName, roleName, role, auditRef, _csrf)
        .then(() => {
            additionsToAddCollection(
                role,
                domainName,
                ':role.',
                'roleMembers',
                'memberName'
            );
            dispatch(addRoleToStore(roleName, role));
            onSuccess(`${domainName}-${roleName}`, false);
        })
        .catch((err) => {
            onFail(err);
        });
};

export const deleteRoleApiCall = async (
    domainName,
    roleName,
    auditRef,
    _csrf,
    dispatch,
    onSuccess,
    onFail
) => {
    await api
        .deleteRole(domainName, roleName, auditRef, _csrf)
        .then(() => {
            dispatch(deleteRoleFromStore(roleName));
            onSuccess(roleName);
        })
        .catch((err) => {
            onFail(err);
        });
};

export const reviewRoleApiCall = async (
    domainName,
    roleName,
    role,
    justification,
    _csrf,
    onSuccess,
    onFail,
    dispatch
) => {
    api.reviewRole(domainName, roleName, role, justification, _csrf)
        .then(() => {
            role.roleMembers = role.roleMembers.filter(
                (member) => member.active !== false
            );
            dispatch(reviewRole(roleName, role.roleMembers));
            onSuccess();
        })
        .catch((err) => {
            onFail(err);
        });
};
