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
import {
    selectActivePoliciesOnly,
    selectPolicy,
} from '../../selectors/policies';
import { mapToList } from '../../utils';
import { selectRoleMembers } from '../../selectors/roles';
import { addRole } from '../roles';
import {
    addAssertion,
    addAssertionConditions,
    deleteAssertion,
    deleteAssertionConditions,
    getPolicies,
} from '../policies';
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
            let category = '';
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
                if (item.name.includes('inbound')) {
                    category = 'inbound';
                    tempData['destination_service'] = serviceName;
                    tempData['source_services'] = [];
                    tempData['assertionIdx'] = assertionItem.id;
                    jsonData['inbound'].push(tempData);
                    index = jsonData['inbound'].length;
                } else if (item.name.includes('outbound')) {
                    category = 'outbound';
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
                    roleName.indexOf(substringPrefix) + substringPrefix.length
                );
                jsonData[category][index - 1]['identifier'] = identifier;
            });
        }
    });
    return jsonData;
};

export const editMicrosegmentationHandler = async (
    domainName,
    roleChanged,
    assertionChanged,
    assertionConditionChanged,
    data,
    _csrf,
    dispatch,
    state
) => {
    let roleName = '';
    let policyName = '';
    let resourceName = '';
    let action = '';
    let tempMembers = [];
    let conditionsList = [];
    let auditRef = 'Updated using MicroSegmentation UI';
    if (data['category'] === 'inbound') {
        roleName =
            'acl.' +
            data['destination_service'] +
            '.inbound-' +
            data['identifier'];
        policyName = 'acl.' + data['destination_service'] + '.inbound';
        resourceName = domainName + ':' + data['destination_service'];
        tempMembers = data['source_services'];
        action =
            data['layer'] +
            '-IN:' +
            data['source_port'] +
            ':' +
            data['destination_port'];
    } else {
        roleName =
            'acl.' + data['source_service'] + '.outbound-' + data['identifier'];
        policyName = 'acl.' + data['source_service'] + '.outbound';
        resourceName = domainName + ':' + data['source_service'];
        tempMembers = data['destination_services'];
        action =
            data['layer'] +
            '-OUT:' +
            data['source_port'] +
            ':' +
            data['destination_port'];
    }

    if (assertionChanged || assertionConditionChanged) {
        for (const condition of data['conditionsList']) {
            const {
                enforcementstate,
                id,
                instances,
                scopeall,
                scopeaws,
                scopeonprem,
                scopegcp,
            } = condition;
            conditionsList.push({
                enforcementstate,
                id,
                instances,
                scopeall,
                scopeaws,
                scopeonprem,
                scopegcp,
            });
        }
    }

    if (roleChanged) {
        let role = {
            name: roleName,
            selfServe: false,
            roleMembers: tempMembers.map((member) => {
                return {
                    memberName: member,
                    expiration: '',
                    reviewReminder: '',
                };
            }),
        };
        await dispatch(addRole(roleName, auditRef, role, _csrf, true));
    }

    if (assertionChanged) {
        let assertion = {
            role: domainName + ':role.' + roleName,
            resource: resourceName,
            effect: 'ALLOW',
            action: action,
            caseSensitive: true,
        };
        await dispatch(getPolicies(domainName));
        const policy = selectPolicy(state, domainName, policyName);
        let foundAssertionMatch = false;
        policy.assertions.forEach((assertion) => {
            if (assertion.action.localeCompare(action) === 0) {
                foundAssertionMatch = true;
            }
        });
        if (foundAssertionMatch) {
            throw {
                status: '500',
                message: {
                    message: 'Policy with the assertion already exists',
                },
            };
        }
        const newAssertion = await dispatch(
            addAssertion(
                domainName,
                policyName,
                assertion.role,
                assertion.resource,
                assertion.action,
                assertion.effect,
                assertion.caseSensitive,
                _csrf
            )
        );
        await dispatch(
            addAssertionConditions(
                domainName,
                policyName,
                newAssertion.id,
                conditionsList,
                auditRef,
                _csrf
            )
        );
        await dispatch(
            deleteAssertion(
                domainName,
                policyName,
                data['assertionIdx'],
                auditRef,
                _csrf
            )
        );
    } else if (assertionConditionChanged) {
        try {
            await dispatch(
                deleteAssertionConditions(
                    domainName,
                    policyName,
                    data['assertionIdx'],
                    auditRef,
                    _csrf
                )
            );
        } catch (err) {
            if (err.status !== 404) {
                throw err;
            }
        }

        await dispatch(
            addAssertionConditions(
                domainName,
                policyName,
                data['assertionIdx'],
                conditionsList,
                auditRef,
                _csrf
            )
        );
    }
};
