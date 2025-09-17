/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

import reduxApiUtils from '../../../server/utils/reduxApiUtils';
import { selectActivePoliciesOnly } from '../../selectors/policies';
import { mapToList } from '../../utils';
import { selectRoleMembers } from '../../selectors/roles';
import { policyDelimiter } from '../../config';

export const getCategoryFromPolicyName = (policyName) => {
    return policyName.slice(policyName.lastIndexOf('.') + 1);
};

export const buildInboundOutbound = (domainName, state) => {
    let jsonData = {
        inbound: [],
        outbound: [],
    };
    const policies = selectActivePoliciesOnly(state);
    policies.forEach((item, index) => {
        if (item.name.startsWith(domainName + policyDelimiter + 'acl.')) {
            let temp = item.name.split('.');
            //sample policy name - ACL.<service-name>.[inbound/outbound]
            let serviceName = temp[temp.length - 2];
            let category = temp[temp.length - 1];
            const assertionsList = mapToList(item.assertions);
            assertionsList.forEach((assertionItem, assertionIdx) => {
                if (
                    !reduxApiUtils
                        .getMicrosegmentationActionRegex()
                        .test(assertionItem.action)
                ) {
                    return;
                }
                let tempData = {};
                let tempProtocol = assertionItem.action.split('-');
                tempData['layer'] = reduxApiUtils.omitUndefined(
                    tempProtocol[0]
                );
                let tempPort = assertionItem.action.split(':');
                tempData['source_port'] = reduxApiUtils.omitUndefined(
                    tempPort[1]
                );
                tempData['destination_port'] = reduxApiUtils.omitUndefined(
                    tempPort[2]
                );
                if (assertionItem.conditions) {
                    tempData['conditionsList'] = [];

                    assertionItem.conditions['conditionsList'].forEach(
                        (condition) => {
                            let tempCondition = {};
                            Object.keys(condition['conditionsMap']).forEach(
                                (key) => {
                                    tempCondition[key] =
                                        condition['conditionsMap'][key][
                                            'value'
                                        ];
                                }
                            );
                            tempCondition['id'] = condition['id'];
                            tempCondition['assertionId'] = assertionItem['id'];
                            tempCondition['policyName'] = item.name;
                            tempData['conditionsList'].push(tempCondition);
                        }
                    );
                }
                let index = 0;
                if (category === 'inbound') {
                    tempData['destination_service'] = serviceName;
                    tempData['source_services'] = [];
                    tempData['assertionIdx'] = assertionItem.id;
                    jsonData['inbound'].push(tempData);
                    index = jsonData['inbound'].length;
                } else if (category === 'outbound') {
                    tempData['source_service'] = serviceName;
                    tempData['destination_services'] = [];
                    tempData['assertionIdx'] = assertionItem.id;
                    jsonData['outbound'].push(tempData);
                    index = jsonData['outbound'].length;
                }
                //assertion convention for microsegmentation:
                //GRANT [Action: <transport layer>-IN / <transport layer>-OUT]:[Source Port]:[Destination Port] [Resource:<service-name>] ON <role-name>
                // role name will be of the form : <domain>:role.<roleName>
                let roleName = assertionItem.role.substring(
                    domainName.length + 6
                );
                const roleMembers = selectRoleMembers(
                    state,
                    domainName,
                    roleName
                );
                if (roleMembers) {
                    roleMembers.forEach((roleMember, idx) => {
                        if (category === 'inbound') {
                            jsonData[category][index - 1][
                                'source_services'
                            ].push(roleMember.memberName);
                        } else if (category === 'outbound') {
                            jsonData[category][index - 1][
                                'destination_services'
                            ].push(roleMember.memberName);
                        }
                    });
                }
                let substringPrefix = '.' + category + '-';
                let identifier = roleName.substring(
                    roleName.lastIndexOf(substringPrefix) +
                        substringPrefix.length
                );
                jsonData[category][index - 1]['identifier'] = identifier;
            });
        }
    });
    return jsonData;
};
