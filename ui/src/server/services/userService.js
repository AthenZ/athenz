/*
 * Copyright 2020 Verizon Media
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
'use strict';

let usersHash = {};
let prevContentLength = 0;
let userServiceImpl = require('./userServiceImpl');
const debug = require('debug')('AthenzUI:server:service:userService');
let VALID_USER_DOMAINS = [];

function getUserFullName(userName) {
    const userArr = userName.split('.');
    if (VALID_USER_DOMAINS.indexOf(userArr[0]) !== -1) {
        const shortId = userArr[1];
        return shortId !== undefined && usersHash[shortId] !== undefined
            ? usersHash[shortId].name
            : undefined;
    }
    return undefined;
}

function prepareUserData(userData, userDomains) {
    VALID_USER_DOMAINS = userDomains.split(',');
    if (userData !== undefined) {
        let usersObj = JSON.parse(userData);
        usersObj.forEach((user) => {
            if (user.enabled_status && user.is_human) {
                usersHash[user.login] = {
                    login: user.login,
                    name: user.gecos,
                };
            }
        });
        debug(
            'updateUserData - Active users count: %o',
            Object.keys(usersHash).length
        );
    } else {
        debug('usersFile is undefined - Cannot process users data');
    }
}

function refreshUserData(config, extServiceClient) {
    return userServiceImpl
        .checkUsersUpdate(
            config.userFilePath,
            config.userFileName,
            extServiceClient
        )
        .then((metadata) => {
            if (metadata && prevContentLength !== metadata.ContentLength) {
                debug('Users file content has changed, about to refresh it');
                prevContentLength = metadata.ContentLength;
                return userServiceImpl
                    .fetchUpdatedUsers(
                        config.userFilePath,
                        config.userFileName,
                        extServiceClient
                    )
                    .then((data) => {
                        return prepareUserData(data, config.userDomains);
                    });
            }
        });
}

module.exports.getUserFullName = getUserFullName;
module.exports.refreshUserData = refreshUserData;
