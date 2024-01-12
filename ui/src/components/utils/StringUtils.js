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

class StringUtils {
    constructor() {}

    isEmpty(str) {
        return !str || str.length === 0;
    }

    getScopeString(item) {
        let scopeStr = '';
        if (item['scopeall'] === 'true') {
            scopeStr += 'All';
        } else if (
            item['scopeonprem'] === 'true' ||
            item['scopeaws'] === 'true' ||
            item['scopegcp'] === 'true'
        ) {
            if (item['scopeonprem'] === 'true') {
                scopeStr += 'OnPrem ';
            }
            if (item['scopeaws'] === 'true') {
                scopeStr += 'AWS ';
            }
            if (item['scopegcp'] === 'true') {
                scopeStr += 'GCP ';
            }
        } else {
            // Backward compatability - if no scope, assume on-prem
            scopeStr += 'OnPrem';
        }
        return scopeStr.split(' ').sort().join(' ');
    }
}

export default StringUtils;
