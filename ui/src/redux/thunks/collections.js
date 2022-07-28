// import { thunkSelectGroup } from '../selectors/group';
// import { getGroup } from './groups';
// import { getRole } from './roles';
// import { thunkSelectRole } from '../selectors/roles';
import {
    addMemberToStore,
    deleteMemberFromStore,
    updateSettingsToStore,
    updateTagsToStore,
} from '../actions/collections';
import API from '../../api';
// import { getFullCollectionName } from './utils/collection';

export const addMember =
    (domainName, collectionName, category, member, auditRef, _csrf) =>
        async (dispatch, getState) => {
            let data = {};
            // if (category === 'group') {
            //     data = thunkSelectGroup(getState(), domainName, collectionName);
            // } else if (category === 'role') {
            //     await dispatch(getRole(domainName, collectionName));
            //     data = thunkSelectRole(getState(), domainName, collectionName);
            // }
            if (member.memberName in data[category + 'Members']) {
                return Promise.reject({
                    body: { message: 'Member already exists' },
                    statusCode: 409,
                });
            } else {
                // TODO roy - fix it get back the member from the api and enter it into the store
                try {
                    await API().addMember(
                        domainName,
                        collectionName,
                        member.memberName,
                        member,
                        auditRef,
                        category,
                        _csrf
                    );
                    // TODO roy - this shouldn't be here
                    member.approved = true;
                    dispatch(
                        addMemberToStore(
                            member,
                            category,
                            collectionName
                            // getFullCollectionName(
                            //     domainName,
                            //     collectionName,
                            //     category
                            // )
                        )
                    );
                    return Promise.resolve();
                } catch (err) {
                    return Promise.reject(err);
                }
            }
        };

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
            // if (category === 'group') {
            //     await dispatch(getGroup(domainName, collectionName));
            //     data = thunkSelectGroup(getState(), domainName, collectionName);
            // } else if (category === 'role') {
            //     await dispatch(getRole(domainName, collectionName));
            //     data = thunkSelectRole(getState(), domainName, collectionName);
            // }
            if (memberName in data[category + 'Members']) {
                try {
                    await API().deleteMember(
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
                            collectionName
                            // getFullCollectionName(
                            //     domainName,
                            //     collectionName,
                            //     category
                            // )
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
                    body: { message: 'Member doesnt exist' },
                    statusCode: 404,
                });
            }
        };

export const updateTags =
    (domain, collectionName, detail, auditRef, _csrf, category) =>
        async (dispatch, getState) => {
            try {
                await API().putMeta(
                    domain,
                    collectionName,
                    detail,
                    auditRef,
                    _csrf,
                    category
                );
                dispatch(
                    updateTagsToStore(
                        // getFullCollectionName(domain, collectionName, category),
                        collectionName,
                        detail.tags,
                        category
                    )
                );
                return Promise.resolve();
            } catch (err) {
                return Promise.reject(err);
            }
        };

export const updateSettings =
    (domainName, collectionMeta, collectionName, _csrf, category) =>
        async (dispatch, getStore) => {
            try {
                await API().putMeta(
                    domainName,
                    collectionName,
                    collectionMeta,
                    'Updated domain Meta using Athenz UI',
                    _csrf,
                    category
                );
                dispatch(
                    updateSettingsToStore(
                        // getFullCollectionName(domainName, collectionName, category),
                        collectionName,
                        collectionMeta,
                        category
                    )
                );
                return Promise.resolve();
            } catch (err) {
                return Promise.reject(err);
            }
        };
