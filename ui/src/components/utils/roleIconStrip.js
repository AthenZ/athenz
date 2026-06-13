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
 * See the License for the specific language governing permissions and limitations
 * under the License.
 */

import { isRoleResourceListManaged } from './resourceOwnership';

/** Icons shown in order: delegated, audit, externally managed (same as RoleRow). */
export function roleVisibleIconCount(role) {
    if (!role) {
        return 0;
    }
    let n = 0;
    if (role.trust) {
        n++;
    }
    if (role.auditEnabled) {
        n++;
    }
    if (isRoleResourceListManaged(role.resourceOwnership)) {
        n++;
    }
    return n;
}

/** Max icons any single row shows in the list — drives shared IconStrip min-width. */
export function maxRoleVisibleIconCount(roles) {
    if (!roles || roles.length === 0) {
        return 0;
    }
    let m = 0;
    for (let i = 0; i < roles.length; i++) {
        const c = roleVisibleIconCount(roles[i]);
        if (c > m) {
            m = c;
        }
    }
    return m;
}

/** CSS min-width for IconStrip: matches RoleRow IconSlot width (1.35em) and gap (2px). */
export function roleIconStripMinWidthStyle(maxIcons) {
    if (maxIcons <= 0) {
        return '0';
    }
    const gapPx = maxIcons > 1 ? (maxIcons - 1) * 2 : 0;
    return `calc(${maxIcons} * 1.35em + ${gapPx}px)`;
}
