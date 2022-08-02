import API from '../../api';
import { storeRoles } from '../actions/domains';
import {
    addRoleToStore,
    deleteRoleFromStore,
    loadRoles,
    returnRoles,
    reviewRoleToStore,
} from '../actions/roles';
import {
    checkIfMemberInAllRoles,
    getRoleApiCall,
    getRolesApiCall,
} from './utils/roles';
import { thunkSelectRole, thunkSelectRoles } from '../selectors/roles';
import {
    buildErrorForDoesntExistCase,
    buildErrorForDuplicateCase,
    getCurrentTime,
    getFullName,
    isExpired,
    listToMap,
} from '../utils';
import { roleDelimiter } from '../config';
import {
    addMemberToStore,
    deleteMemberFromStore,
} from '../actions/collections';

export const addRole =
    (roleName, auditRef, role, _csrf) => async (dispatch, getState) => {
        let domainName = getState().roles.domainName;
        await dispatch(getRoles(domainName));
        let roles = thunkSelectRoles(getState());
        if (getFullName(domainName, roleDelimiter, roleName) in roles) {
            return Promise.reject(buildErrorForDuplicateCase('Role', roleName));
        } else {
            try {
                let roleFromApi = await API().addRole(
                    domainName,
                    roleName,
                    role,
                    auditRef,
                    _csrf
                );
                // TODO roy - shouldn't be here
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
        let roles = thunkSelectRoles(getState());
        if (!(getFullName(domainName, roleDelimiter, roleName) in roles)) {
            return Promise.reject(
                buildErrorForDoesntExistCase('Role', roleName)
            );
        } else {
            try {
                await API().deleteRole(domainName, roleName, auditRef, _csrf);
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
    // auditLog is a unique filed which the backend returns only in getRole api call
    if (role.auditLog) {
        dispatch(returnRoles());
    } else {
        try {
            await getRoleApiCall(domainName, roleName, dispatch);
            return Promise.resolve();
        } catch (e) {
            return Promise.reject(e);
        }
    }
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
                body: {
                    message: `${member.memberName} is already in all roles`,
                },
            });
        } else {
            try {
                let memberFromApi = await API().addMemberToRoles(
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

// TODO roy - this function is not working
export const reviewRole =
    (domainName, role, justification, _csrf) => async (dispatch, getState) => {
        await dispatch(getRole(domainName, role.name));
        try {
            // TODO roy - problem the func sends only the extands and delete list need to get all the remain member from the api
            //TODO roy - when getting back from api enter into the store
            await API().reviewRole(
                domainName,
                role.name,
                role,
                justification,
                _csrf
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
            await API().deleteRoleMember(
                domainName,
                deleteName,
                auditRef,
                _csrf
            );
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
