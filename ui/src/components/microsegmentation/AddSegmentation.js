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
import React from 'react';
import ButtonGroup from '../denali/ButtonGroup';
import Input from '../denali/Input';
import InputLabel from '../denali/InputLabel';
import Member from '../member/Member';
import styled from '@emotion/styled';
import { colors } from '../denali/styles';
import AddModal from '../modal/AddModal';
import RequestUtils from '../utils/RequestUtils';
import InputDropdown from '../denali/InputDropdown';
import Icon from '../denali/icons/Icon';
import {
    MODAL_TIME_OUT,
    SEGMENTATION_CATEGORIES,
    SEGMENTATION_PROTOCOL,
} from '../constants/constants';
import NameUtils from '../utils/NameUtils';
import RadioButtonGroup from '../denali/RadioButtonGroup';
import CheckBox from '../denali/CheckBox';
import MicrosegmentationValidationModal from '../modal/MicrosegmentationValidationModal';

const SectionDiv = styled.div`
    align-items: flex-start;
    display: flex;
    flex-flow: row nowrap;
    padding: 10px 10px;
`;

const CheckBoxSectionDiv = styled.div`
    padding-top: 15px;
`;

const StyledInputLabel = styled(InputLabel)`
    float: left;
    font-size: 14px;
    font-weight: 700;
    padding-top: 12px;
    width: 20%;
`;

const StyledInputLabelHost = styled(InputLabel)`
    float: left;
    font-size: 14px;
    font-weight: 700;
    padding-top: 12px;
    width: 8%;
`;

const StyledButtonGroup = styled(ButtonGroup)`
    height: 40px;
    width: 200px;
`;

const StyledInput = styled(Input)`
    width: 750px;
    padding-top: 12px;
`;

const StyledInputHost = styled(Input)`
    width: 415px;
    padding-top: 12px;
`;

const AddCircleDiv = styled.div`
    margin-top: 5px;
    margin-left: 10px;
    padding-top: 12px;
`;

const RemoveCircleDiv = styled.div`
    margin-top: 5px;
    margin-left: 10px;
    padding-top: 12px;
`;

const ContentDiv = styled.div`
    flex: 1 1;
    margin-right: 1px;
`;

const ValidationErrorDiv = styled.div`
    flex: 1 1;
    margin-right: 1px;
    padding-top: 8px;
`;

const ValidationErrorStatusDiv = styled.div`
    flex: 1 1;
    margin-right: 1px;
    padding-top: 20px;
`;

const ValidationErrorSpan = styled.span`
    font: 300 16px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
`;

const AddMemberDiv = styled.div`
    display: flex;
`;

const StyledIncludedMembersDiv = styled.div`
    width: 65%;
`;

const SectionsDiv = styled.div`
    width: 1000px;
    text-align: left;
    background-color: ${colors.white};
`;

const StyledRadioButtonGroup = styled(RadioButtonGroup)`
    padding-top: 18px;
    width: 26%;
`;

const StyledInputDropdown = styled(InputDropdown)`
    padding-top: 12px;
`;

const StyledCheckBox = styled(CheckBox)``;

export default class AddSegmentation extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.categoryChanged = this.categoryChanged.bind(this);
        this.addMember = this.addMember.bind(this);
        this.onSubmit = this.onSubmit.bind(this);
        this.onEditSubmit = this.onEditSubmit.bind(this);
        this.loadServices = this.loadServices.bind(this);
        this.changeService = this.changeService.bind(this);
        this.protocolChanged = this.protocolChanged.bind(this);
        this.createPolicy = this.createPolicy.bind(this);
        this.validatePort = this.validatePort.bind(this);
        this.inputChanged = this.inputChanged.bind(this);
        this.handleInputChange = this.handleInputChange.bind(this);
        this.handleAddClick = this.handleAddClick.bind(this);
        this.handleRemoveClick = this.handleRemoveClick.bind(this);
        this.editValidationPolicy = this.editValidationPolicy.bind(this);
        this.validateMicrosegmentationPolicy =
            this.validateMicrosegmentationPolicy.bind(this);

        this.state = {
            category: this.props.editMode
                ? this.props.data['category']
                : 'inbound',
            isCategory: this.props.editMode
                ? this.props.data['category'] === 'inbound'
                : true,
            inboundDestinationService:
                this.props.editMode && this.props.data['category'] === 'inbound'
                    ? this.props.data['destination_service']
                    : '',
            outboundSourceService:
                this.props.editMode &&
                this.props.data['category'] === 'outbound'
                    ? this.props.data['source_service']
                    : '',
            destinationPort: this.props.editMode
                ? this.props.data['destination_port']
                : '',
            sourceServiceMembers: '',
            destinationServiceMembers: '',
            sourcePort: this.props.editMode
                ? this.props.data['source_port']
                : '1024-65535',
            protocol: this.props.editMode ? this.props.data['layer'] : '',
            newMemberName: '',
            memberExpiry: '',
            memberReviewReminder: '',
            members: this.props.editMode
                ? this.props.data['category'] === 'inbound'
                    ? this.props.data['source_services'].map((str) => ({
                          memberName: str,
                          approved: true,
                      }))
                    : this.props.data['destination_services'].map((str) => ({
                          memberName: str,
                          approved: true,
                      }))
                : [],
            protocolValid: true,
            action: '',
            resource: '',
            destinationServiceList: [],
            identifier: this.props.editMode
                ? this.props.data['identifier']
                : '',
            justification: '',
            PESList:
                this.props.editMode && this.props.data['conditionsList']
                    ? JSON.parse(
                          JSON.stringify(this.props.data['conditionsList'])
                      )
                    : [{ enforcementstate: 'report', instances: '', id: 1 }],
            data: props.data,
            validationCheckbox: false,
            saving: 'todo',
            validationError: 'none',
            validationStatus: 'valid',
        };
    }

    componentDidMount() {
        this.loadServices();
    }

    categoryChanged(button) {
        if (!this.props.editMode) {
            this.setState({
                category: button.name,
                isCategory: !this.state.isCategory, //Setting isCategory true for inbound and false for outbound through out the code
                errorMessage: '',
                saving: 'todo',
            });
        }
    }

    protocolChanged(chosen) {
        if (chosen && chosen.value != null) {
            this.setState({
                protocol: chosen.value,
                protocolValid: true,
            });
        } else {
            this.setState({
                protocolValid: false,
            });
        }
    }

    inputChanged(evt, key) {
        let value = '';

        if (key === 'validationCheckbox') {
            value = evt.target.checked;
        } else if (evt.target) {
            value = evt.target.value;
        } else {
            value = evt ? evt : '';
        }
        this.setState({
            [key]: value,
        });
    }

    editValidationPolicy() {
        this.setState({
            validationStatus: '',
            validationError: 'none',
        });
    }

    addMember() {
        let sourceServiceName = this.state.isCategory
            ? this.state.sourceServiceMembers
            : this.state.destinationServiceMembers;
        let members = this.state.members;

        if (!sourceServiceName) {
            return;
        }
        let names = NameUtils.splitNames(sourceServiceName);
        for (let i = 0; i < names.length; i++) {
            members.push({
                memberName: names[i],
            });
        }

        if (this.state.isCategory) {
            this.setState({
                sourceServiceMembers: '',
            });
        } else {
            this.setState({
                destinationServiceMembers: '',
            });
        }
        this.setState({
            members,
        });
    }

    deleteMember(idx) {
        let members = this.state.members;
        // this if is done to avoid [null] condition
        if (members.length === 1) {
            members = [];
        } else {
            members.splice(idx, 1);
        }
        this.setState({ members });
    }

    createPolicy(policyName, roleName, resource, action) {
        //Validating ACL policy and adding/updating assertion. if get policy threw a 404 then create a new policy
        var foundAssertionMatch = false;

        return new Promise((resolve, reject) => {
            this.api
                .getPolicy(this.props.domain, policyName)
                .then((data) => {
                    data.assertions.forEach((element) => {
                        if (element.action.localeCompare(action) === 0) {
                            foundAssertionMatch = true;
                        }
                    });
                    if (foundAssertionMatch) {
                        this.api
                            .deleteRole(
                                this.props.domain,
                                roleName,
                                'deleted using Microsegmentation UI because of same assertion',
                                this.props._csrf
                            )
                            .then(() => {
                                reject(
                                    'Same policy already exists with a different identifier'
                                );
                            })
                            .catch((err) => {
                                reject(RequestUtils.xhrErrorCheckHelper(err));
                            });
                    } else {
                        this.api
                            .addAssertion(
                                this.props.domain,
                                policyName,
                                roleName,
                                resource,
                                action,
                                'ALLOW',
                                true,
                                this.props._csrf
                            )
                            .then((data) => {
                                this.api
                                    .addAssertionConditions(
                                        this.props.domain,
                                        policyName,
                                        data.id,
                                        this.state.PESList,
                                        this.state.justification
                                            ? this.state.justification
                                            : 'Microsegmentaion Assertion Condition using Athenz UI',
                                        this.props._csrf
                                    )
                                    .then((conditionData) => {
                                        this.props.onSubmit();
                                    })
                                    .catch((err) => {
                                        reject(
                                            RequestUtils.xhrErrorCheckHelper(
                                                err
                                            )
                                        );
                                    });
                            })
                            .catch((err) => {
                                reject(RequestUtils.xhrErrorCheckHelper(err));
                            });
                    }
                })
                .catch((err) => {
                    if (err && err.statusCode === 404) {
                        this.api
                            .addPolicy(
                                this.props.domain,
                                policyName,
                                roleName,
                                resource,
                                action,
                                'ALLOW',
                                true,
                                this.props._csrf
                            )
                            .then(() => {
                                this.api
                                    .getAssertionId(
                                        this.props.domain,
                                        policyName,
                                        roleName,
                                        resource,
                                        action,
                                        'ALLOW'
                                    )
                                    .then((assertionId) => {
                                        this.api
                                            .addAssertionConditions(
                                                this.props.domain,
                                                policyName,
                                                assertionId,
                                                this.state.PESList,
                                                this.state.justification
                                                    ? this.state.justification
                                                    : 'Microsegmentaion Assertion Condition using Athenz UI',
                                                this.props._csrf
                                            )
                                            .then((conditionData) => {
                                                this.props.onSubmit();
                                            })
                                            .catch((err) => {
                                                reject(
                                                    RequestUtils.xhrErrorCheckHelper(
                                                        err
                                                    )
                                                );
                                            });
                                    })
                                    .catch((err) => {
                                        reject(
                                            RequestUtils.fetcherErrorCheckHelper(
                                                err
                                            )
                                        );
                                    });
                            })
                            .catch((err) => {
                                reject(
                                    RequestUtils.fetcherErrorCheckHelper(err)
                                );
                            });
                    } else {
                        reject(RequestUtils.xhrErrorCheckHelper(err));
                    }
                });
        });
    }

    validatePort(port) {
        var regex = new RegExp('^[0-9-,]*$');
        var result = {
            error: 0,
            port: port,
        };

        if (!regex.test(port)) {
            this.setState({
                errorMessage: "Port can only contain numbers, '-' and ','",
                saving: 'todo',
            });
            result.error = 1;
            return result;
        }

        let ports = port.split(',');
        for (var i = 0; i < ports.length; i++) {
            if (ports[i].indexOf('-') != -1) {
                let range = ports[i].split('-');
                let start = parseInt(range[0]);
                let end = parseInt(range[1]);
                if (
                    range.length != 2 ||
                    isNaN(start) ||
                    isNaN(end) ||
                    start < 1 ||
                    end < 1 ||
                    start > end ||
                    start > 65535 ||
                    end > 65535
                ) {
                    this.setState({
                        errorMessage:
                            'Invalid port: ' +
                            ports[i] +
                            '. Valid range of port numbers: 1-65535',
                        saving: 'todo',
                    });
                    result.error = 1;
                    return result;
                }
            } else if (ports[i] < 0 && ports[i] > 65535) {
                this.setState({
                    errorMessage:
                        'Invalid port: ' +
                        ports[i] +
                        'Valid range of port numbers: 1-65535',
                    saving: 'todo',
                });
                result.error = 1;
                return result;
            } else {
                ports[i] = ports[i] + '-' + ports[i];
            }
        }

        result.port = ports.join(',');
        return result;
    }

    validateFields() {
        if (this.state.isCategory) {
            if (
                !this.state.inboundDestinationService ||
                this.state.inboundDestinationService === ''
            ) {
                this.setState({
                    errorMessage: 'Destination service is required.',
                    saving: 'todo',
                });
                return 1;
            }

            if (
                !this.state.destinationPort ||
                this.state.destinationPort === ''
            ) {
                this.setState({
                    errorMessage: 'Destination Port is required.',
                    saving: 'todo',
                });
                return 1;
            }

            if (!this.state.sourcePort || this.state.sourcePort === '') {
                this.setState({
                    errorMessage: 'Source port is required.',
                    saving: 'todo',
                });
                return 1;
            }

            if (!this.state.protocol || this.state.protocol === '') {
                this.setState({
                    errorMessage: 'Protocol is required.',
                    saving: 'todo',
                });
                return 1;
            }
        } else {
            if (
                !this.state.outboundSourceService ||
                this.state.outboundSourceService === ''
            ) {
                this.setState({
                    errorMessage: 'Source service is required.',
                    saving: 'todo',
                });
                return 1;
            }

            if (!this.state.sourcePort || this.state.sourcePort === '') {
                this.setState({
                    errorMessage: 'Source port is required.',
                    saving: 'todo',
                });
                return 1;
            }

            if (
                !this.state.destinationPort ||
                this.state.destinationPort === ''
            ) {
                this.setState({
                    errorMessage: 'Destination Port is required.',
                    saving: 'todo',
                });
                return 1;
            }

            if (!this.state.protocol || this.state.protocol === '') {
                this.setState({
                    errorMessage: 'Protocol is required.',
                    saving: 'todo',
                });
                return 1;
            }
        }

        if (
            this.props.justificationRequired &&
            (this.state.justification === undefined ||
                this.state.justification.trim() === '')
        ) {
            this.setState({
                errorMessage: 'Justification is required to add a member.',
                saving: 'todo',
            });
            return 1;
        }

        return 0;
    }

    validateMicrosegmentationPolicy(
        category,
        roleMembers,
        inboundDestinationService,
        outboundSourceService,
        sourcePort,
        destinationPort,
        protocol,
        assertionId,
        skipValidation
    ) {
        return new Promise((resolve, reject) => {
            if (this.state.validationCheckbox === true && !skipValidation) {
                this.api
                    .validateMicrosegmentationPolicy(
                        category,
                        roleMembers,
                        inboundDestinationService,
                        outboundSourceService,
                        sourcePort,
                        destinationPort,
                        protocol,
                        this.props.domain,
                        assertionId,
                        this.props._csrf
                    )
                    .then((data) => {
                        if (data.status !== 'VALID') {
                            this.setState({
                                validationError: data.errors.join('\r\n'),
                                validationStatus: data.status,
                                saving: 'todo',
                            });
                            reject();
                        } else {
                            resolve();
                        }
                    })
                    .catch((err) => {
                        reject(RequestUtils.fetcherErrorCheckHelper(err));
                    });
            } else {
                resolve();
            }
        });
    }

    createRole(role) {
        return new Promise((resolve, reject) => {
            this.api
                .getRole(this.props.domain, role.name)
                .then((existingRole) => {
                    reject(
                        'The identifier is already being used for this service. Please use a new identifier.'
                    );
                })
                .catch((err) => {
                    if (err && err.statusCode === 404) {
                        this.api
                            .addRole(
                                this.props.domain,
                                role.name,
                                role,
                                this.state.justification
                                    ? this.state.justification
                                    : 'Microsegmentaion Role creation',
                                this.props._csrf
                            )
                            .then((data) => {
                                resolve();
                            })
                            .catch((err) => {
                                reject(RequestUtils.xhrErrorCheckHelper(err));
                            });
                    } else {
                        reject(RequestUtils.fetcherErrorCheckHelper(err));
                    }
                });
        });
    }

    onSubmit(evt, skipValidation = false) {
        this.setState({
            saving: 'saving',
        });

        // validate fields
        if (this.validateFields()) {
            return;
        }

        // add all members to one list
        this.addMember();

        let source = this.validatePort(this.state.sourcePort);
        let destination = this.validatePort(this.state.destinationPort);

        if (source.error || destination.error) {
            return;
        }

        const sourcePort = source.port;
        const destinationPort = destination.port;

        //set the policy and assertion values based on ACL category
        var roleName, action, policyName, resource;

        if (this.state.isCategory) {
            roleName =
                'acl.' +
                this.state.inboundDestinationService +
                '.' +
                SEGMENTATION_CATEGORIES[0].name +
                '-' +
                this.state.identifier;
            action =
                this.state.protocol +
                '-' +
                'IN' +
                ':' +
                sourcePort +
                ':' +
                destinationPort;
            policyName =
                'acl.' +
                this.state.inboundDestinationService +
                '.' +
                SEGMENTATION_CATEGORIES[0].name;
            resource = this.state.inboundDestinationService;
        } else {
            roleName =
                'acl.' +
                this.state.outboundSourceService +
                '.' +
                SEGMENTATION_CATEGORIES[1].name +
                '-' +
                this.state.identifier;
            action =
                this.state.protocol +
                '-' +
                'OUT' +
                ':' +
                sourcePort +
                ':' +
                destinationPort;
            policyName =
                'acl.' +
                this.state.outboundSourceService +
                '.' +
                SEGMENTATION_CATEGORIES[1].name;
            resource = this.state.outboundSourceService;
        }

        //populate the role object with members and role name
        let role = { name: roleName };
        role.roleMembers =
            this.state.members.filter((member) => {
                return (
                    member.memberName != null || member.memberName != undefined
                );
            }) || [];

        // check if validation of policy has been enabled
        // if enabled then validate microsegmentation policy against network policy

        let assertionId = -1;

        this.validateMicrosegmentationPolicy(
            this.state.category,
            role.roleMembers,
            this.state.inboundDestinationService,
            this.state.outboundSourceService,
            sourcePort,
            destinationPort,
            this.state.protocol,
            assertionId,
            skipValidation
        )
            .then(() => {
                return this.createRole(role);
            })
            .then(() => {
                return this.createPolicy(
                    policyName,
                    role.name,
                    resource,
                    action
                );
            })
            .catch((err) => {
                if (skipValidation) {
                    this.setState({
                        errorMessage: err,
                        saving: 'todo',
                        validationError: 'none',
                    });
                } else {
                    this.setState({
                        errorMessage: err,
                        saving: 'todo',
                    });
                }
            });
    }

    onEditSubmit(evt, skipValidation = false) {
        this.setState({
            saving: 'saving',
        });
        if (this.validateFields()) {
            return;
        }

        this.addMember();

        let source = this.validatePort(this.state.sourcePort);
        let destination = this.validatePort(this.state.destinationPort);

        if (source.error || destination.error) {
            return;
        }

        let roleChanged = false;
        let assertionChanged = false;
        let assertionConditionChanged = false;

        let updatedData = JSON.parse(JSON.stringify(this.props.data));

        let originalMembers = [];
        if (this.props.data['category'] === 'inbound') {
            originalMembers = this.props.data['source_services'];
        } else {
            originalMembers = this.props.data['destination_services'];
        }

        var originalMembersHash = originalMembers.reduce(function (map, obj) {
            map[obj] = 1;
            return map;
        }, {});

        for (let member of this.state.members) {
            if (!originalMembersHash[member.memberName]) {
                roleChanged = true;
                break;
            }
        }
        if (
            this.state.members.length !==
            Object.keys(originalMembersHash).length
        ) {
            roleChanged = true;
        }

        if (roleChanged) {
            let newMembers = [];
            for (let member of this.state.members) {
                newMembers.push(member.memberName);
            }
            if (this.props.data['category'] === 'inbound') {
                updatedData['source_services'] = newMembers;
            } else {
                updatedData['destination_services'] = newMembers;
            }
        }

        if (
            this.props.data['destination_port'] !== this.state.destinationPort
        ) {
            assertionChanged = true;
            assertionConditionChanged = true;
        } else if (this.props.data['source_port'] !== this.state.sourcePort) {
            assertionChanged = true;
            assertionConditionChanged = true;
        } else if (this.props.data['layer'] !== this.state.protocol) {
            assertionChanged = true;
            assertionConditionChanged = true;
        }

        if (assertionChanged) {
            updatedData['destination_port'] = destination.port;
            updatedData['source_port'] = source.port;
            updatedData['layer'] = this.state.protocol;
            updatedData['conditionsList'] = this.state.PESList;
        } else {
            const comparer = (otherArray) => (current) =>
                otherArray.filter(
                    (other) =>
                        other.instances == current.instances &&
                        other.enforcementstate == current.enforcementstate &&
                        other.id == current.id
                ).length == 0;

            if (this.props.data['conditionList']) {
                let x = this.props.data['conditionsList'].filter(
                    comparer(this.state.PESList)
                );
                let y = this.state.PESList.filter(
                    comparer(this.props.data['conditionsList'])
                );

                if (x.length != 0 || y.length != 0) {
                    assertionConditionChanged = true;
                    updatedData['conditionsList'] = this.state.PESList;
                }
            } else {
                assertionConditionChanged = true;
                updatedData['conditionsList'] = this.state.PESList;
            }
        }

        let assertionId = this.state.data.assertionIdx;

        this.validateMicrosegmentationPolicy(
            this.state.category,
            this.state.members,
            this.state.inboundDestinationService,
            this.state.outboundSourceService,
            source.port,
            destination.port,
            this.state.protocol,
            assertionId,
            skipValidation
        )
            .then(() => {
                if (
                    roleChanged ||
                    assertionChanged ||
                    assertionConditionChanged
                ) {
                    this.api
                        .editMicrosegmentation(
                            this.props.domain,
                            roleChanged,
                            assertionChanged,
                            assertionConditionChanged,
                            updatedData,
                            this.props._csrf
                        )
                        .then(() => {
                            this.props.onSubmit();
                        })
                        .catch((err) => {
                            this.setState({
                                errorMessage:
                                    RequestUtils.fetcherErrorCheckHelper(err),
                                saving: 'todo',
                                validationError: 'none',
                            });
                        });
                } else {
                    this.props.onCancel();
                }
            })
            .catch((err) => {
                if (skipValidation) {
                    this.setState({
                        errorMessage: err,
                        saving: 'todo',
                        validationError: 'none',
                    });
                } else {
                    this.setState({
                        errorMessage: err,
                        saving: 'todo',
                    });
                }
            });
    }

    loadServices() {
        this.api
            .getServices(this.props.domain)
            .then((data) => {
                for (var i = 0; i < data.length; i++) {
                    let name = NameUtils.getShortName('.', data[i]['name']);
                    data[i]['name'] = name;
                    data[i]['value'] = name;
                    delete data[i]['modified'];
                }
                this.setState({
                    destinationServiceList: data,
                });
                setTimeout(
                    () =>
                        this.setState({
                            showSuccess: false,
                        }),
                    MODAL_TIME_OUT
                );
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.fetcherErrorCheckHelper(err),
                    saving: 'todo',
                });
            });
    }

    changeService(chosen, key) {
        if (chosen && chosen.name != null) {
            const name = chosen.name;
            this.setState({
                [key]: name,
            });
        }
    }

    handleInputChange(e, index) {
        const { name, value } = e.target;
        const list = [...this.state.PESList];

        if (name.includes('enforcementStateRadioButton')) {
            list[index]['enforcementstate'] = value;
            if (list.length == 2) {
                if (value === 'report') {
                    list[1]['enforcementstate'] = 'enforce';
                } else {
                    list[1]['enforcementstate'] = 'report';
                }
            }
        } else {
            list[index]['instances'] = value;
        }
        this.setState({
            PESList: list,
        });
    }

    handleAddClick() {
        let enforcementstate = 'report';
        if (this.state.PESList[0]['enforcementstate'] === 'report') {
            enforcementstate = 'enforce';
        }
        this.setState({
            PESList: [
                ...this.state.PESList,
                { enforcementstate: enforcementstate, instances: '', id: 2 },
            ],
        });
    }

    handleRemoveClick(index) {
        const list = [...this.state.PESList];
        list.splice(index, 1);
        list[0]['id'] = 1;
        this.setState({
            PESList: list,
        });
    }

    render() {
        const inputs = [
            {
                label: 'Report',
                value: 'report',
            },
            {
                label: 'Enforce',
                value: 'enforce',
            },
        ];

        let members = this.state.members
            ? this.state.members.map((item, idx) => {
                  // dummy place holder so that it can be be used in the form
                  item.approved = true;
                  let remove = this.deleteMember.bind(this, idx);
                  return (
                      <Member
                          key={idx}
                          item={item}
                          onClickRemove={remove}
                          noanim
                      />
                  );
              })
            : '';

        let sections = (
            <SectionsDiv>
                <SectionDiv>
                    <StyledInputLabel>ACL Category</StyledInputLabel>
                    <StyledButtonGroup
                        buttons={SEGMENTATION_CATEGORIES}
                        selectedName={
                            this.props.data
                                ? this.state.data['category']
                                : this.state.category
                        }
                        onClick={this.categoryChanged}
                        noanim
                    />
                </SectionDiv>
                <SectionDiv>
                    <StyledInputLabel>Identifier</StyledInputLabel>
                    <StyledInput
                        placeholder='Enter a unique identifier for this ACL policy'
                        value={this.state.identifier}
                        onChange={(event) =>
                            this.inputChanged(event, 'identifier')
                        }
                        noanim
                        fluid
                        disabled={this.props.editMode}
                    />
                </SectionDiv>
                <SectionDiv>
                    <StyledInputLabel>
                        {this.state.isCategory
                            ? 'Destination Service'
                            : 'Source Service'}
                    </StyledInputLabel>
                    <StyledInputDropdown
                        name='destinationService'
                        options={this.state.destinationServiceList}
                        value={
                            this.props.editMode
                                ? this.state.isCategory
                                    ? this.state.inboundDestinationService
                                    : this.state.outboundSourceService
                                : undefined
                        }
                        onChange={(item) =>
                            this.changeService(
                                item,
                                this.state.isCategory
                                    ? 'inboundDestinationService'
                                    : 'outboundSourceService'
                            )
                        }
                        placeholder={
                            this.state.isCategory
                                ? 'Select Destination Service'
                                : 'Select Source Service'
                        }
                        noanim
                        filterable
                        disabled={this.props.editMode}
                    />
                </SectionDiv>

                {this.state.PESList.map((x, i) => {
                    return (
                        <SectionDiv>
                            <StyledInputLabel>
                                Policy Enforcement State
                            </StyledInputLabel>
                            <StyledRadioButtonGroup
                                name={'enforcementStateRadioButton' + i}
                                inputs={inputs}
                                selectedValue={x.enforcementstate}
                                onChange={(e) => this.handleInputChange(e, i)}
                                disabled={i == 1}
                            />

                            <StyledInputLabelHost>Hosts</StyledInputLabelHost>
                            <StyledInputHost
                                placeholder='Comma separated list, Leave blank to apply to all hosts'
                                value={x.instances}
                                name={'instances' + i}
                                onChange={(e) => this.handleInputChange(e, i)}
                                noanim
                                error={x.instances.length > 2048}
                                message={
                                    x.instances.length > 2048
                                        ? 'Limit is 2048 characters. Contact #athenz channel on slack'
                                        : ''
                                }
                                fluid
                            />
                            {this.state.PESList.length < 2 ? (
                                <AddCircleDiv>
                                    <Icon
                                        icon={'add-circle'}
                                        isLink
                                        color={colors.icons}
                                        size='1.75em'
                                        onClick={this.handleAddClick}
                                    />
                                </AddCircleDiv>
                            ) : (
                                <RemoveCircleDiv>
                                    <Icon
                                        icon={'minus'}
                                        isLink
                                        color={colors.icons}
                                        size='1.75em'
                                        onClick={() =>
                                            this.handleRemoveClick(i)
                                        }
                                    />
                                </RemoveCircleDiv>
                            )}
                        </SectionDiv>
                    );
                })}

                <SectionDiv>
                    <StyledInputLabel>
                        {this.state.isCategory
                            ? 'Destination Port(s)'
                            : 'Source Port(s)'}
                    </StyledInputLabel>
                    <ContentDiv>
                        <StyledInput
                            placeholder='eg: 4443'
                            value={
                                this.state.isCategory
                                    ? this.state.destinationPort
                                    : this.state.sourcePort
                            }
                            onChange={(event) =>
                                this.inputChanged(
                                    event,
                                    this.state.isCategory
                                        ? 'destinationPort'
                                        : 'sourcePort'
                                )
                            }
                            noanim
                            fluid
                        />
                    </ContentDiv>
                </SectionDiv>
                <SectionDiv>
                    <StyledInputLabel>
                        {this.state.isCategory
                            ? 'Source Service'
                            : 'Destination Service'}
                    </StyledInputLabel>
                    <StyledInput
                        placeholder='eg: yamas.api, sys.auth.zms'
                        value={
                            this.state.isCategory
                                ? this.state.sourceServiceMembers
                                : this.state.destinationServiceMembers
                        }
                        onChange={(event) =>
                            this.inputChanged(
                                event,
                                this.state.isCategory
                                    ? 'sourceServiceMembers'
                                    : 'destinationServiceMembers'
                            )
                        }
                        noanim
                        fluid
                    />
                </SectionDiv>
                <SectionDiv>
                    <StyledInputLabel />
                    <StyledIncludedMembersDiv>
                        {members}
                    </StyledIncludedMembersDiv>
                </SectionDiv>
                <SectionDiv>
                    <StyledInputLabel>
                        {this.state.isCategory
                            ? 'Source Port(s)'
                            : 'Destination Port(s)'}
                    </StyledInputLabel>
                    <ContentDiv>
                        <AddMemberDiv>
                            <StyledInput
                                placeholder='eg: 1024-65535'
                                value={
                                    this.state.isCategory
                                        ? this.state.sourcePort
                                        : this.state.destinationPort
                                }
                                onChange={(event) =>
                                    this.inputChanged(
                                        event,
                                        this.state.isCategory
                                            ? 'sourcePort'
                                            : 'destinationPort'
                                    )
                                }
                                noanim
                                fluid
                            />
                        </AddMemberDiv>
                    </ContentDiv>
                </SectionDiv>
                <SectionDiv>
                    <StyledInputLabel>Protocol</StyledInputLabel>
                    <StyledInputDropdown
                        name='protocol'
                        defaultSelectedValue={this.state.protocol}
                        options={SEGMENTATION_PROTOCOL}
                        onChange={this.protocolChanged}
                        placeholder='Select Protocol'
                        noanim
                        filterable
                    />
                </SectionDiv>
                {this.props.pageFeatureFlag['policyValidation'] && (
                    <SectionDiv>
                        <StyledInputLabel>Validation</StyledInputLabel>
                        <CheckBoxSectionDiv>
                            <StyledCheckBox
                                checked={this.state.validationCheckbox}
                                name={
                                    'checkbox-validate-policy' +
                                    this.state.isCategory
                                }
                                id={
                                    'checkbox-validate-policy' +
                                    this.state.isCategory
                                }
                                key={
                                    'checkbox-validate-policy' +
                                    this.state.isCategory
                                }
                                label='Validate Microsegmentation policy against PES network policy'
                                onChange={(event) =>
                                    this.inputChanged(
                                        event,
                                        'validationCheckbox'
                                    )
                                }
                            />
                        </CheckBoxSectionDiv>
                    </SectionDiv>
                )}
                {this.props.justificationRequired && (
                    <SectionDiv>
                        <StyledInputLabel>Justification</StyledInputLabel>
                        <ContentDiv>
                            <StyledInput
                                value={this.state.justification}
                                onChange={(event) =>
                                    this.inputChanged(event, 'justification')
                                }
                                placeholder='Enter justification here'
                            />
                        </ContentDiv>
                    </SectionDiv>
                )}
            </SectionsDiv>
        );

        let validationResponseSections = (
            <SectionsDiv>
                <SectionDiv>
                    <StyledInputLabel>Status</StyledInputLabel>
                    <ValidationErrorStatusDiv>
                        {this.state.validationStatus}
                    </ValidationErrorStatusDiv>
                </SectionDiv>
                <SectionDiv>
                    <StyledInputLabel>Errors</StyledInputLabel>
                    <ValidationErrorDiv>
                        <pre>
                            <ValidationErrorSpan>
                                {this.state.validationError}
                            </ValidationErrorSpan>
                        </pre>
                    </ValidationErrorDiv>
                </SectionDiv>
            </SectionsDiv>
        );

        return (
            <div data-testid='add-segment'>
                {this.state.validationError === 'none' && (
                    <AddModal
                        isOpen={this.props.showAddSegment}
                        cancel={this.props.onCancel}
                        submit={
                            this.props.editMode
                                ? this.onEditSubmit
                                : this.onSubmit
                        }
                        title={
                            this.props.editMode
                                ? `Edit Microsegmentation ACL Policy`
                                : `Add Microsegmentation ACL Policy`
                        }
                        errorMessage={this.state.errorMessage}
                        saving={this.state.saving}
                        sections={sections}
                        width={'1050px'}
                        bodyMaxHeight={'90%'}
                        modalHeight={'85vh'}
                    />
                )}
                {this.state.validationError !== 'none' && (
                    <MicrosegmentationValidationModal
                        isOpen={this.props.showAddSegment}
                        editPolicy={this.editValidationPolicy}
                        submit={
                            this.props.editMode
                                ? this.onEditSubmit
                                : this.onSubmit
                        }
                        title={`Validation Errors`}
                        editMode={this.props.editMode}
                        saving={this.state.saving}
                        sections={validationResponseSections}
                        width={'1050px'}
                        bodyHeight={'90%'}
                        modalHeight={'85vh'}
                    />
                )}
            </div>
        );
    }
}
