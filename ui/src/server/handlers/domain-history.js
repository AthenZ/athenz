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

module.exports = function (
    req,
    resource,
    params,
    config,
    callback,
    userService,
    errorHandler
) {
    let history = [];
    history.push({
        action: 'action',
        who: 'principal',
        whoFull: 'principal full',
        whatEntity: 'resource',
        when: '2020-01-01T10:00:00.000Z',
        details: 'detailed json',
        epoch: 'epoch timestamp',
        why: 'justification',
    });
    history.sort(function (a, b) {
        return b.epoch - a.epoch;
    });
    return callback(null, history);
};
