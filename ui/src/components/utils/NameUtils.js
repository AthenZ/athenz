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
import { PENDING_STATE_ENUM } from '../constants/constants';

class NameUtils {
    static getShortName(key, name) {
        const idx = name.lastIndexOf(key);
        if (idx !== -1) {
            return name.substr(idx + key.length);
        }
        return name;
    }

    static getResourceName(resource, domainId) {
        resource = resource.trim();
        return resource.includes(':') ? resource : `${domainId}:${resource}`;
    }

    static getRoleAssertionName(role, domainId) {
        role = role.trim();
        return role.includes(':role.') ? role : `${domainId}:role.${role}`;
    }

    static getFlatPickrKey(key) {
        return key.replace(/\./g, '_').replace(/\W/g, '_');
    }

    static splitNames(names) {
        return (names || '')
            .replace(/[\r\n\s]+/g, ',')
            .split(',')
            .map((n) => n.trim())
            .filter((n) => n);
    }

    static getPendingStateToDisplay(pendingState) {
        switch (pendingState) {
            case PENDING_STATE_ENUM.ADD:
                return 'adding member';
            case PENDING_STATE_ENUM.DELETE:
                return 'deleting member';
            default:
                return '';
        }
    }
}

export default NameUtils;
