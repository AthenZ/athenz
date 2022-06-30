import API from '../../api';
import { loadingInProcess, loadingSuccess } from '../actions/loading';
import { storeRoles } from '../actions/domains';
import { loadRoles, loadRoleUsers, returnRoles } from '../actions/roles';
import {
    addRoleApiCall,
    deleteRoleApiCall,
    getRoleApiCall,
    getRolesApiCall,
    reviewRoleApiCall,
} from './utils/roles';
import { thunkSelectRole, thunkSelectRoleUsers } from '../selectors/roles';
import { getExpiryTime } from '../utils';

const api = API();

export const addRole =
    (roleName, auditRef, role, _csrf, onSuccess, onFail) =>
    async (dispatch, getState) => {
        let domainName = getState().roles.domainName;
        await dispatch(getRoles(domainName));
        let roles = getState().roles.roles;
        // problem if going to else maybe was added between refreshes
        if (roleName in roles) {
            onFail({
                statusCode: 409,
                body: { message: `${roleName} already exist` },
            });
        } else {
            await addRoleApiCall(
                domainName,
                roleName,
                role,
                auditRef,
                _csrf,
                dispatch,
                onSuccess,
                onFail
            );
        }
    };

export const deleteRole =
    (roleName, auditRef, _csrf, onSuccess, onFail) =>
    async (dispatch, getState) => {
        let domainName = getState().roles.domainName;
        await dispatch(getRoles(domainName));
        let roles = getState().roles.roles;
        console.log('in delete the role are: ', roles);
        if (!(roleName in roles)) {
            onFail({
                statusCode: 409,
                body: { message: `${roleName} does not exist` },
            });
        } else {
            await deleteRoleApiCall(
                domainName,
                roleName,
                auditRef,
                _csrf,
                dispatch,
                onSuccess,
                onFail
            );
        }
    };

export const getRole = (domainName, roleName) => async (dispatch, getState) => {
    await dispatch(getRoles(domainName));
    let role = thunkSelectRole(getState(), roleName);
    if (role.roleMembers && role.expiry > 0) {
    } else {
        await getRoleApiCall(domainName, roleName, dispatch);
    }
};

// export const addMemberToRoles =
//     (checkedRoles, member, justification, _csrf, onSuccess, onFail) =>
//     async (dispatch, getState) => {
//         let domainName = getState().roles.domainName;
//         await dispatch(getRoles(domainName));
//         for (let roleName of checkedRoles) {
//             await dispatch(getRole(domainName, roleName));
//         }
//         let roles = thunkSelectRoles(getState());
//     };

export const getRoles = (domainName) => async (dispatch, getState) => {
    if (getState().roles.expiry) {
        if (getState().roles.domainName !== domainName) {
            dispatch(loadingInProcess('StoreRoles'));
            dispatch(storeRoles(getState().roles));
            if (
                getState().domains[domainName] &&
                getState().domains[domainName].roles &&
                getState().domains[domainName].roles.expiry > 0
            ) {
                dispatch(
                    loadRoles(
                        getState().domains[domainName].roles,
                        domainName,
                        getState().domains[domainName].roles.expiry
                    )
                );
            } else {
                await getRolesApiCall(domainName, dispatch);
                dispatch(loadingSuccess('StoreRoles'));
            }
        } else if (getState().roles.expiry <= 0) {
            await getRolesApiCall(domainName, dispatch);
        } else {
            dispatch(returnRoles());
        }
    } else {
        await getRolesApiCall(domainName, dispatch);
    }
};

export const getRoleMembers =
    (domainName, onSuccess, onFail) => async (dispatch, getState) => {
        let roleUsers = thunkSelectRoleUsers(getState());
        if (roleUsers.expiry === undefined || roleUsers.expiry <= 0) {
            api.getRoleMembers(domainName)
                .then((members) => {
                    let expiry = getExpiryTime();
                    roleUsers.members = members.members;
                    for (let i = 0; i < members.members.length; i++) {
                        let name = members.members[i].memberName;
                        roleUsers.expand[name] = members.members[i].memberRoles;
                        roleUsers.fullNames[name] =
                            members.members[i].memberFullName;
                        roleUsers.contents[name] = null;
                        roleUsers.expandArray[name] = false;
                    }
                    roleUsers.expiry = expiry;
                    dispatch(loadRoleUsers(roleUsers));
                    onSuccess();
                })
                .catch((error) => {
                    onFail(error);
                });
        }
    };

export const reviewRole =
    (domainName, roleName, role, justification, _csrf, onSuccess, onFail) =>
    async (dispatch, getState) => {
        await dispatch(getRole(domainName, roleName));
        await reviewRoleApiCall(
            domainName,
            roleName,
            role,
            justification,
            _csrf,
            onSuccess,
            onFail,
            dispatch
        );
    };
