export const ADD_MEMBER_TO_STORE = 'ADD_MEMBER_TO_STORE';
export const addMemberToStore = (member, category, collectionName) => ({
    type: ADD_MEMBER_TO_STORE,
    payload: {
        member,
        category,
        collectionName,
    },
});

export const DELETE_MEMBER_FROM_STORE = 'DELETE_MEMBER_FROM_STORE';
export const deleteMemberFromStore = (
    memberName,
    category,
    collectionName
) => ({
    type: DELETE_MEMBER_FROM_STORE,
    payload: {
        memberName,
        category,
        collectionName,
    },
});

export const UPDATE_SETTING_TO_STORE = 'UPDATE_SETTING_TO_STORE';
export const updateSettingsToStore = (
    collectionName,
    collectionSettings,
    category
) => ({
    type: UPDATE_SETTING_TO_STORE,
    payload: {
        collectionName,
        collectionSettings,
        category,
    },
});

export const UPDATE_TAGS_TO_STORE = 'UPDATE_TAGS_TO_STORE';
export const updateTagsToStore = (
    collectionName,
    collectionTags,
    category
) => ({
    type: UPDATE_TAGS_TO_STORE,
    payload: {
        collectionName,
        collectionTags,
        category,
    },
});
