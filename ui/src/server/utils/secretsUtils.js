'use strict';

function getAuthHeader(accessToken) {
    let accessTokenStr = accessToken;
    try {
        const accessTokenObj = JSON.parse(accessToken);
        return accessTokenObj.token_type + ' ' + accessTokenObj.access_token;
    } catch (e) {
        return 'Bearer ' + accessTokenStr;
    }
}

module.exports.authHeader = getAuthHeader;
