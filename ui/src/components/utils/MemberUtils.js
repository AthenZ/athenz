/*
 * Copyright The Athenz Authors
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
import RegexUtils from './RegexUtils';
import { getUsers } from '../../redux/utils';
import { USER_DOMAIN } from '../constants/constants';

export default class MemberUtils {
    static getUserNames(name, regex) {
        let names = (name || '')
            .replace(/[\r\n\s]+/g, ',')
            .split(',')
            .map((n) => n.trim())
            .filter((n) => n);

        let invalidUsers = [];
        let validUsers = [];
        names.forEach((name) => {
            if (RegexUtils.validate(name, regex)) {
                validUsers.push(name);
            } else {
                invalidUsers.push(name);
            }
        });

        return {
            invalidUsers,
            validUsers,
        };
    }

    static userSearch(part, userList) {
        if (part.startsWith(USER_DOMAIN)) {
            part = part.substring(USER_DOMAIN.length + 1);
        }
        return getUsers(part, userList).then((r) => {
            let usersArr = [];
            r.forEach((u) =>
                usersArr.push({
                    name: u.name + ' [' + USER_DOMAIN + '.' + u.login + ']',
                    value: USER_DOMAIN + '.' + u.login,
                })
            );
            return usersArr;
        });
    }
}
