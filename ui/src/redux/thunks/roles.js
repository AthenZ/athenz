import API from '../../api';
import { loadingInProcess, loadingSuccess } from '../actions/loading';
import { storeRoles } from '../actions/domains';
import {
    addMemberToRolesToStore,
    addRoleToStore,
    deleteRoleFromStore,
    loadRoles,
    loadRoleUsers,
    returnRoles,
    reviewRoleToStore,
} from '../actions/roles';
import {
    addMemberToRolesApiCall,
    getRoleApiCall,
    getRolesApiCall,
} from './utils/roles';
import {
    thunkSelectRole,
    thunkSelectRoleMembers,
    thunkSelectRoles,
    thunkSelectRoleUsers,
} from '../selectors/roles';
import {
    getCurrentTime,
    getExpiryTime,
    getFullName,
    isExpired,
    listToMap,
} from '../utils';
import { roleDelimiter } from '../config';
import {
    addMemberToStore,
    deleteMemberFromStore,
} from '../actions/collections';

const api = API();

export const addRole =
    (roleName, auditRef, role, _csrf) => async (dispatch, getState) => {
        let domainName = getState().roles.domainName;
        await dispatch(getRoles(domainName));
        let roles = getState().roles.roles;
        // problem if going to else maybe was added between refreshes
        if (roleName in roles) {
            return new Promise((resolve, reject) => {
                reject({
                    statusCode: 409,
                    body: { message: `role ${roleName} already exist` },
                });
            });
        } else {
            try {
                let roleFromApi = await api.addRole(
                    domainName,
                    roleName,
                    role,
                    auditRef,
                    _csrf
                );
                role.expiry = getExpiryTime();
                role.modified = getCurrentTime();
                role.name = getFullName(domainName, roleDelimiter, roleName);
                role.roleMembers = listToMap(role.roleMembers, 'memberName');
                dispatch(
                    addRoleToStore(
                        getFullName(domainName, roleDelimiter, roleName),
                        role
                    )
                );
                return Promise.resolve();
            } catch (error) {
                return Promise.reject(error);
            }
        }
    };

export const deleteRole =
    (roleName, auditRef, _csrf) => async (dispatch, getState) => {
        let domainName = getState().roles.domainName;
        await dispatch(getRoles(domainName));
        let roles = getState().roles.roles;
        if (!(getFullName(domainName, roleDelimiter, roleName) in roles)) {
            return new Promise((resolve, reject) => {
                reject({
                    statusCode: 409,
                    body: { message: `role ${roleName} does not exist` },
                });
            });
        } else {
            try {
                await api.deleteRole(domainName, roleName, auditRef, _csrf);
                dispatch(
                    deleteRoleFromStore(
                        getFullName(domainName, roleDelimiter, roleName)
                    )
                );
                return Promise.resolve(roleName);
            } catch (error) {
                return Promise.reject(error);
            }
        }
    };

export const getRole = (domainName, roleName) => async (dispatch, getState) => {
    await dispatch(getRoles(domainName));
    let role = thunkSelectRole(getState(), domainName, roleName);
    if (role.roleMembers && role.expiry > 0) {
    } else {
        try {
            await getRoleApiCall(domainName, roleName, dispatch);
            return Promise.resolve();
        } catch (e) {
            return Promise.reject(e);
        }
    }
};

const checkIfMemberInAllRoles = (domainName, state, roleList, memberName) => {
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

export const addMemberToRoles =
    (domainName, checkedRoles, member, justification, _csrf) =>
    async (dispatch, getState) => {
        await dispatch(getRoles(domainName));
        if (
            checkIfMemberInAllRoles(
                domainName,
                getState(),
                checkedRoles,
                member.memberName
            )
        ) {
            return Promise.reject({
                statusCode: 409,
                body: { message: `${member.memberName} already in all roles` },
            });
        } else {
            try {
                let memberFromApi = await api.addMemberToRoles(
                    domainName,
                    checkedRoles,
                    member.memberName,
                    member,
                    justification,
                    _csrf
                );
                for (let roleName of checkedRoles) {
                    dispatch(
                        addMemberToStore(
                            member,
                            'role',
                            getFullName(domainName, roleDelimiter, roleName)
                        )
                    );
                }
                // dispatch(addMemberToRolesToStore(member, newCheckedRole));
                return Promise.resolve();
            } catch (error) {
                return Promise.reject(error);
            }
        }
    };

export const getRoles = (domainName) => async (dispatch, getState) => {
    if (getState().roles.expiry) {
        if (getState().roles.domainName !== domainName) {
            dispatch(storeRoles(getState().roles));
            if (
                getState().domains[domainName] &&
                getState().domains[domainName].roles &&
                !isExpired(getState().domains[domainName].roles.expiry)
            ) {
                dispatch(
                    loadRoles(
                        getState().domains[domainName].roles.roles,
                        domainName,
                        getState().domains[domainName].roles.expiry
                    )
                );
            } else {
                await getRolesApiCall(domainName, dispatch);
            }
        } else if (isExpired(getState().roles.expiry)) {
            await getRolesApiCall(domainName, dispatch);
        } else {
            dispatch(returnRoles());
        }
    } else {
        await getRolesApiCall(domainName, dispatch);
    }
};

export const reviewRole =
    (domainName, role, justification, _csrf) => async (dispatch, getState) => {
        await dispatch(getRole(domainName, role.name));
        try {
            // TODO roy - when getting back from api enter into the store
            await api.reviewRole(
                domainName,
                role.name,
                role,
                justification,
                _csrf
            );
            role.roleMembers = role.roleMembers.filter(
                (member) => member.active !== false
            );
            dispatch(
                reviewRoleToStore(
                    getFullName(domainName, roleDelimiter, role.name),
                    role.roleMembers
                )
            );
            return Promise.resolve();
        } catch (error) {
            return Promise.reject(error);
        }
    };

export const deleteMemberFromAllRoles =
    (domainName, deleteName, auditRef, _csrf) => async (dispatch, getState) => {
        try {
            await api.deleteRoleMember(domainName, deleteName, auditRef, _csrf);
            let roles = thunkSelectRoles(getState());
            for (let [roleName, role] of Object.entries(roles)) {
                if (deleteName in role.roleMembers) {
                    dispatch(
                        deleteMemberFromStore(deleteName, 'role', roleName)
                    );
                }
            }
            return Promise.resolve();
        } catch (error) {
            return Promise.reject(error);
        }
    };
