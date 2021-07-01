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
import DateUtils from '../utils/DateUtils';
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
import Modal from '../denali/Modal';

const SectionDiv = styled.div`
    align-items: flex-start;
    display: flex;
    flex-flow: row nowrap;
    padding: 10px 10px;
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
`;

const StyledInputHost = styled(Input)`
    width: 415px;
`;

const AddCircleDiv = styled.div`
    margin-top: 5px;
    margin-left: 10px;
`;

const RemoveCircleDiv = styled.div`
    margin-top: 5px;
    margin-left: 10px;
`;

const ContentDiv = styled.div`
    flex: 1 1;
    margin-right: 1px;
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

export default class AddSegmentation extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.categoryChanged = this.categoryChanged.bind(this);
        this.addMember = this.addMember.bind(this);
        this.onSubmit = this.onSubmit.bind(this);
        this.loadServices = this.loadServices.bind(this);
        this.changeService = this.changeService.bind(this);
        this.protocolChanged = this.protocolChanged.bind(this);
        this.handlePolicy = this.handlePolicy.bind(this);
        this.handleMembers = this.handleMembers.bind(this);
        this.validatePort = this.validatePort.bind(this);
        this.inputChanged = this.inputChanged.bind(this);
        this.addFields = this.addFields.bind(this);
        this.handleInputChange = this.handleInputChange.bind(this);
        this.handleAddClick = this.handleAddClick.bind(this);
        this.handleRemoveClick = this.handleRemoveClick.bind(this);
        this.state = {
            category: 'inbound',
            isCategory: true,
            inboundDestinationService: '',
            outboundDestinationService: '',
            inboundSourceService: '',
            outboundSourceService: '',
            destinationPort: '',
            sourceServiceMembers: '',
            destinationServiceMembers: '',
            sourcePort: '',
            protocol: '',
            newMemberName: '',
            memberExpiry: '',
            memberReviewReminder: '',
            members: [],
            protocolValid: true,
            action: '',
            resource: '',
            destinationServiceList: [],
            identifier: '',
            justification: '',
            PESList: [{ enforcementState: 'report', instances: '' }],
        };
    }

    componentDidMount() {
        this.loadServices();
    }

    categoryChanged(button) {
        this.setState({
            category: button.name,
            isCategory: !this.state.isCategory, //Setting isCategory true for inbound and false for outbound through out the code
            errorMessage: '',
        });
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
        if (evt.target) {
            value = evt.target.value;
        } else {
            value = evt ? evt : '';
        }
        this.setState({
            [key]: value,
        });
    }

    addFields() {
        return this.state.values.map((el, i) => (
            <div key={i}>
                <input
                    type='text'
                    value={el || ''}
                    onChange={this.handleChange.bind(this, i)}
                />
                <input
                    type='button'
                    value='remove'
                    onClick={this.removeClick.bind(this, i)}
                />
            </div>
        ));
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
            // sourceService: '',
        });
    }

    deleteMember(idx) {
        let members = this.state.members;
        // this if is done to avoid [null] condition
        if (members.length === 1) {
            members = [];
        } else {
            delete members[idx];
        }
        this.setState({ members });
    }

    handlePolicy(policyName, roleName, resource, action) {
        //Validating ACL policy and adding/updating assertion. if get policy threw a 404 then create a new policy
        var foundAssertionMatch = false;
        this.api
            .getPolicy(this.props.domain, policyName)
            .then((data) => {
                data.assertions.forEach((element) => {
                    if (element.action.localeCompare(action) === 0) {
                        foundAssertionMatch = true;
                    }
                });
                if (foundAssertionMatch) {
                    if (!this.state.errorMessage) {
                        this.props.onSubmit();
                    }
                } else {
                    this.api
                        .addAssertion(
                            this.props.domain,
                            policyName,
                            roleName,
                            resource,
                            action,
                            'ALLOW',
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
                                        : 'Micro-segmentaion Assertion Condition using Athenz UI',
                                    this.props._csrf
                                )
                                .then((conditionData) => {
                                    this.props.onSubmit();
                                })
                                .catch((err) => {
                                    this.setState({
                                        errorMessage:
                                            RequestUtils.xhrErrorCheckHelper(
                                                err
                                            ),
                                    });
                                });
                        })
                        .catch((err) => {
                            this.setState({
                                errorMessage:
                                    RequestUtils.xhrErrorCheckHelper(err),
                            });
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
                                                : 'Micro-segmentaion Assertion Condition using Athenz UI',
                                            this.props._csrf
                                        )
                                        .then((conditionData) => {
                                            this.props.onSubmit();
                                        })
                                        .catch((err) => {
                                            this.setState({
                                                errorMessage:
                                                    RequestUtils.xhrErrorCheckHelper(
                                                        err
                                                    ),
                                            });
                                        });
                                })
                                .catch((err) => {
                                    this.setState({
                                        errorMessage:
                                            RequestUtils.xhrErrorCheckHelper(
                                                err
                                            ),
                                    });
                                });
                        })
                        .catch((err) => {
                            this.setState({
                                errorMessage:
                                    RequestUtils.xhrErrorCheckHelper(err),
                            });
                        });
                } else {
                    this.setState({
                        errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                    });
                }
            });
    }

    handleMembers(role) {
        let promises = [];
        role.roleMembers.forEach((members) => {
            let membership = {
                memberName: members.memberName, //membership is a must object with atleast members in it.
                approved: true,
            };
            promises.push(
                this.api.addMember(
                    this.props.domain,
                    role.name,
                    members.memberName,
                    membership,
                    this.state.justification
                        ? this.state.justification
                        : 'added for micro-segmentation',
                    'role',
                    this.props._csrf
                )
            );
        });
        Promise.all(promises)
            .then(() => {
                this.setState({
                    errorMessage: '',
                });
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
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
                    start < 1 ||
                    end < 1 ||
                    start > end ||
                    start > 65535 ||
                    end > 65535
                ) {
                    this.setState({
                        errorMessage: 'Invalid port: ' + ports[i],
                    });
                    result.error = 1;
                    return result;
                }
            } else if (ports[i] > 0 && ports[i] <= 65535) {
                ports[i] = ports[i] + '-' + ports[i];
            } else {
                this.setState({
                    errorMessage: 'Port has to be in the range of 1-65535',
                });
                result.error = 1;
                return result;
            }
        }

        result.port = ports.join(',');
        return result;
    }

    onSubmit() {
        this.setState({
            errorMessage: '',
        });
        this.addMember();

        //Input field validation

        if (!this.state.identifier || this.state.identifier === '') {
            this.setState({
                errorMessage: 'Identifier is required.',
            });
            return;
        }

        if (this.state.isCategory) {
            if (
                !this.state.inboundDestinationService ||
                this.state.inboundDestinationService === ''
            ) {
                this.setState({
                    errorMessage: 'Destination service is required.',
                });
                return;
            }

            if (
                !this.state.destinationPort ||
                this.state.destinationPort === ''
            ) {
                this.setState({
                    errorMessage: 'Destination Port is required.',
                });
                return;
            }

            if (this.state.members <= 0) {
                this.setState({
                    errorMessage: 'Atlease one source service is required.',
                });
                return;
            }

            if (!this.state.sourcePort || this.state.sourcePort === '') {
                this.setState({
                    errorMessage: 'Source port is required.',
                });
                return;
            }

            if (!this.state.protocol || this.state.protocol === '') {
                this.setState({
                    errorMessage: 'Protocol is required.',
                });
                return;
            }
        } else {
            if (
                !this.state.outboundSourceService ||
                this.state.outboundSourceService === ''
            ) {
                this.setState({
                    errorMessage: 'Source service is required.',
                });
                return;
            }

            if (!this.state.sourcePort || this.state.sourcePort === '') {
                this.setState({
                    errorMessage: 'Source port is required.',
                });
                return;
            }

            if (this.state.members <= 0) {
                this.setState({
                    errorMessage:
                        'Atlease one destination service is required.',
                });
                return;
            }

            if (
                !this.state.destinationPort ||
                this.state.destinationPort === ''
            ) {
                this.setState({
                    errorMessage: 'Destination Port is required.',
                });
                return;
            }

            if (!this.state.protocol || this.state.protocol === '') {
                this.setState({
                    errorMessage: 'Protocol is required.',
                });
                return;
            }
        }

        if (
            this.props.justificationRequired &&
            (this.state.justification === undefined ||
                this.state.justification.trim() === '')
        ) {
            this.setState({
                errorMessage: 'Justification is required to add a member.',
            });
            return;
        }

        let sourcePort = this.validatePort(this.state.sourcePort).port;
        let destinationPort = this.validatePort(
            this.state.destinationPort
        ).port;

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

        //Check for the role and if it is missing add it otherwise contniue with policy aseertion update
        this.api
            .getRole(this.props.domain, role.name)
            .then((existingRole) => {
                this.setState({
                    errorMessage:
                        'The identifier is already being used for this service. Please use a new identifier.',
                });
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
                                : 'Micro-segmentaion Role creation',
                            this.props._csrf
                        )
                        .then((data) => {
                            this.handlePolicy(
                                policyName,
                                role.name,
                                resource,
                                action
                            );
                        })
                        .catch((err) => {
                            this.setState({
                                errorMessage:
                                    RequestUtils.xhrErrorCheckHelper(err),
                            });
                        });
                } else {
                    this.setState({
                        errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                    });
                }
            });
    }

    loadServices() {
        this.api
            .getServices(this.props.domain)
            .then((data) => {
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
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    changeService(chosen, key) {
        if (chosen && chosen.name != null) {
            var name = chosen.name;
            var cleanServiceName = name.substring(name.lastIndexOf('.') + 1);
            this.setState({
                [key]: cleanServiceName,
            });
        }
    }

    handleInputChange(e, index) {
        const { name, value } = e.target;
        const list = [...this.state.PESList];

        if (name.includes('enforcementStateRadioButton')) {
            list[index]['enforcementState'] = value;
            if (list.length == 2) {
                if (value === 'report') {
                    list[1]['enforcementState'] = 'enforce';
                } else {
                    list[1]['enforcementState'] = 'report';
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
        let enforcementState = 'report';
        if (this.state.PESList[0]['enforcementState'] === 'report') {
            enforcementState = 'enforce';
        }
        this.setState({
            PESList: [
                ...this.state.PESList,
                { enforcementState: enforcementState, instances: '' },
            ],
        });
    }

    handleRemoveClick(index) {
        const list = [...this.state.PESList];
        list.splice(index, 1);
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
                        selectedName={this.state.category}
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
                    />
                </SectionDiv>
                <SectionDiv>
                    <StyledInputLabel>
                        {this.state.isCategory
                            ? 'Destination Service'
                            : 'Source Service'}
                    </StyledInputLabel>
                    <InputDropdown
                        name='destinationService'
                        defaultSelectedValue={
                            this.state.isCategory
                                ? this.state.inboundDestinationService
                                : this.state.outboundSourceService
                        }
                        options={this.state.destinationServiceList}
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
                                ? 'Enter Destination Service'
                                : 'Enter Source Service'
                        }
                        noclear
                        noanim
                        filterable
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
                                selectedValue={x.enforcementState}
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
                            ? 'Destination Port'
                            : 'Source Port'}
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
                        placeholder='eg: yamas.api, sys.auth.zms (click + button to add)'
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

                    <AddCircleDiv>
                        <Icon
                            icon={'add-circle'}
                            isLink
                            color={colors.icons}
                            size='1.75em'
                            onClick={this.addMember}
                        />
                    </AddCircleDiv>
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
                            ? 'Source Port'
                            : 'Destination Port'}
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
                    <InputDropdown
                        name='protocol'
                        defaultSelectedValue={this.state.protocol}
                        options={SEGMENTATION_PROTOCOL}
                        onChange={this.protocolChanged}
                        placeholder='Select Protocol'
                        noclear
                        noanim
                        filterable
                    />
                </SectionDiv>
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
        return (
            <div data-testid='add-segment'>
                <AddModal
                    isOpen={this.props.showAddSegment}
                    cancel={this.props.onCancel}
                    submit={this.onSubmit}
                    title={`Add Micro Segmentation ACL Policy`}
                    errorMessage={this.state.errorMessage}
                    sections={sections}
                    width={'1050px'}
                    bodyMaxHeight={'530px'}
                />
            </div>
        );
    }
}
