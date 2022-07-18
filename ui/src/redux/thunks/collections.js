import { thunkSelectGroup } from '../selectors/group';
import { getGroup } from './groups';
import { getRole } from './roles';
import { thunkSelectRole } from '../selectors/roles';
import { getFullName } from '../utils';
import { groupDelimiter, roleDelimiter } from '../config';
import {
    addMemberToStore,
    deleteMemberFromStore,
} from '../actions/collections';
import API from '../../api';
import {
    addDomainTagToStore,
    updateDomainSettings,
} from '../actions/domain-data';
import { addGroupTagsToStore, updateGroupSettings } from '../actions/groups';
import { addRoleTagsToStore, updateRoleSettings } from '../actions/roles';

const getFullCollectionName = (domainName, collectionName, category) => {
    if (category === 'group') {
        return getFullName(domainName, groupDelimiter, collectionName);
    } else if (category === 'role') {
        return getFullName(domainName, roleDelimiter, collectionName);
    }
};

const api = API();
export const addMember =
    (domainName, collectionName, category, member, auditRef, _csrf) =>
    async (dispatch, getState) => {
        let data = {};
        if (category === 'group') {
            data = thunkSelectGroup(getState(), domainName, collectionName);
        } else if (category === 'role') {
            await dispatch(getRole(domainName, collectionName));
            data = thunkSelectRole(getState(), domainName, collectionName);
        }
        if (member.memberName in data[category + 'Members']) {
            return Promise.reject({
                body: { message: 'Member already exists' },
                statusCode: 409,
            });
        } else {
            // TODO roy - fix it get back the member from the api and enter it into the store
            try {
                await api.addMember(
                    domainName,
                    collectionName,
                    member.memberName,
                    member,
                    auditRef,
                    category,
                    _csrf
                );
                member.approved = true;
                dispatch(
                    addMemberToStore(
                        member,
                        category,
                        getFullCollectionName(
                            domainName,
                            collectionName,
                            category
                        )
                    )
                );
                return Promise.resolve();
            } catch (err) {
                return Promise.reject(err);
            }
        }
    };

// TODO change it remove expiry from role
export const deleteMember =
    (
        domainName,
        collectionName,
        category,
        memberName,
        auditRef,
        pending,
        _csrf
    ) =>
    async (dispatch, getState) => {
        let data = {};
        if (category === 'group') {
            await dispatch(getGroup(domainName, collectionName));
            data = thunkSelectGroup(getState(), domainName, collectionName);
        } else if (category === 'role') {
            await dispatch(getRole(domainName, collectionName));
            data = thunkSelectRole(getState(), domainName, collectionName);
        }
        if (memberName in data[category + 'Members']) {
            try {
                await api.deleteMember(
                    domainName,
                    collectionName,
                    memberName,
                    auditRef,
                    false,
                    category,
                    _csrf
                );
                dispatch(
                    deleteMemberFromStore(
                        memberName,
                        category,
                        getFullCollectionName(
                            domainName,
                            collectionName,
                            category
                        )
                    )
                );
                // if (category === 'role') {
                //     dispatch(deleteRoleUsersMember(collection, memberName));
                // }
                return Promise.resolve();
            } catch (err) {
                return Promise.reject(err);
            }
        } else {
            return Promise.reject({
                body: { message: 'Member does not exist' },
                statusCode: 404,
            });
        }
    };

export const updateTags =
    (domain, collectionName, detail, auditRef, _csrf, category) =>
    async (dispatch, getState) => {
        try {
            await api.putMeta(
                domain,
                collectionName,
                detail,
                auditRef,
                _csrf,
                category
            );
            if (category === 'domain') {
                dispatch(addDomainTagToStore(detail.tags));
            } else if (category === 'group') {
                dispatch(
                    addGroupTagsToStore(
                        getFullCollectionName(domain, collectionName, category),
                        detail.tags
                    )
                );
            } else if (category === 'role') {
                dispatch(
                    addRoleTagsToStore(
                        getFullCollectionName(domain, collectionName, category),
                        detail.tags
                    )
                );
            }
            return Promise.resolve();
        } catch (err) {
            return Promise.reject(err);
        }
    };

export const updateSettings =
    (domainName, collectionMeta, collectionName, _csrf, category) =>
    async (dispatch, getStore) => {
        try {
            await api.putMeta(
                domainName,
                collectionName,
                collectionMeta,
                'Updated domain Meta using Athenz UI',
                _csrf,
                category
            );
            if (category === 'domain') {
                dispatch(updateDomainSettings(collectionMeta));
            } else if (category === 'group') {
                dispatch(
                    updateGroupSettings(
                        getFullCollectionName(
                            domainName,
                            collectionName,
                            category
                        ),
                        collectionMeta
                    )
                );
            } else if (category === 'role') {
                dispatch(
                    updateRoleSettings(
                        getFullCollectionName(
                            domainName,
                            collectionName,
                            category
                        ),
                        collectionMeta
                    )
                );
            }
            return Promise.resolve();
        } catch (err) {
            return Promise.reject(err);
        }
    };
