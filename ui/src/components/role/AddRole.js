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
import React from 'react';
import Button from '../denali/Button';
import ButtonGroup from '../denali/ButtonGroup';
import Input from '../denali/Input';
import InputLabel from '../denali/InputLabel';
import RoleMember from './RoleMember';
import styled from '@emotion/styled';
import Flatpicker from '../flatpicker/FlatPicker';
import { colors } from '../denali/styles';
import AddModal from '../modal/AddModal';
import DateUtils from '../utils/DateUtils';
import RequestUtils from '../utils/RequestUtils';

const CATEGORIES = [
    {
        label: 'Regular',
        name: 'regular',
    },
    {
        label: 'Delegated',
        name: 'delegated',
    },
];

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
    width: 25%;
`;

const StyledButtonGroup = styled(ButtonGroup)`
    height: 40px;
    width: 200px;
`;

const StyledInput = styled(Input)`
    width: 500px;
`;

const StyledInputUser = styled(Input)`
    width: 270px;
    margin-top: 5px;
`;

const ContentDiv = styled.div`
    flex: 1 1;
    margin-right: 10px;
`;

const AddMemberDiv = styled.div`
    display: flex;
`;

const StyledIncludedMembersDiv = styled.div`
    width: 65%;
`;

const SectionsDiv = styled.div`
    width: 900px;
    text-align: left;
    background-color: ${colors.white};
`;

const FlatPickrStyled = styled.div`
    flex: 1 1;
    margin-left: 10px;
    margin-right: 10px;
    & > div input {
        position: relative;
        font: 300 14px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
        background-color: rgba(53, 112, 244, 0.05);
        box-shadow: none;
        color: rgb(48, 48, 48);
        height: 16px;
        min-width: 50px;
        text-align: left;
        border-width: 2px;
        border-style: solid;
        border-color: transparent;
        border-image: initial;
        border-radius: 2px;
        flex: 1 0 auto;
        margin: 0;
        margin-right: 10px;
        margin-top: 5px;
        outline: none;
        padding: 0.6em 12px;
        transition: background-color 0.2s ease-in-out 0s,
            color 0.2s ease-in-out 0s, border 0.2s ease-in-out 0s;
        width: 77%;
    }
`;

const ButtonDiv = styled.div`
    margin-left: 10px;
`;

const StyledButton = styled(Button)`
    width: 125px;
`;

export default class AddRole extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.categoryChanged = this.categoryChanged.bind(this);
        this.addMember = this.addMember.bind(this);
        this.delegateChanged = this.delegateChanged.bind(this);
        this.onSubmit = this.onSubmit.bind(this);
        this.dateUtils = new DateUtils();
        this.state = {
            saving: 'nope',
            category: 'regular',
            name: '',
            newMemberName: '',
            newMemberDate: '',
            members: [],
            trustDomain: '',
            date: '',
        };
    }

    categoryChanged(button) {
        this.setState({
            category: button.name,
        });
    }

    inputChanged(key, evt) {
        let value = '';
        if (evt.target) {
            value = evt.target.value;
        } else {
            value = evt ? evt : '';
        }
        this.setState({ [key]: value });
    }

    getJustification() {
        if (this.props.justificationRequired) {
            return (
                <SectionDiv>
                    <StyledInputLabel>Justification</StyledInputLabel>
                    <ContentDiv>
                        <StyledInput
                            id='justification'
                            name='justification'
                            value={this.state.justification}
                            onChange={this.inputChanged.bind(
                                this,
                                'justification'
                            )}
                            autoComplete={'off'}
                            placeholder='Enter justification here'
                        />
                    </ContentDiv>
                </SectionDiv>
            );
        }
    }

    addMember() {
        let name = this.state.newMemberName;
        let date =
            this.state.newMemberDate && this.state.newMemberDate.length > 0
                ? this.state.newMemberDate
                : '';
        let members = this.state.members;

        if (!name) {
            return;
        }
        let names = (name || '')
            .replace(/[\r\n\s]+/g, ',')
            .split(',')
            .map((n) => n.trim())
            .filter((n) => n);

        for (let i = 0; i < names.length; i++) {
            members.push({
                memberName: names[i],
                expiration: date
                    ? this.dateUtils.uxDatetimeToRDLTimestamp(date)
                    : '',
            });
        }

        this.setState({
            members,
            newMemberName: '',
            newMemberDate: '',
        });
    }

    deleteMember(idx) {
        let members = this.state.members;
        // this if is done to avoid [null] condition
        if (members.length === 1) {
            members = null;
        } else {
            delete members[idx];
        }
        this.setState({ members });
    }

    delegateChanged(evt) {
        this.setState({
            trustDomain: evt.target.value,
        });
    }

    onSubmit() {
        let roleName = this.state.name;

        if (!roleName || roleName === '') {
            this.setState({
                errorMessage: 'Role name is required.',
            });
            return;
        }

        let role = { name: roleName };
        if (this.state.category === 'regular') {
            role.roleMembers = this.state.members || [];
            if (this.state.newMemberName && this.state.newMemberName !== '') {
                role.roleMembers.push({
                    memberName: this.state.newMemberName,
                    expiration: this.dateUtils.uxDatetimeToRDLTimestamp(
                        this.state.newMemberDate
                    ),
                });
            }
        }
        if (this.state.category === 'delegated') {
            role.trust = this.state.trustDomain;
            if (!role.trust) {
                this.setState({
                    errorMessage: 'Delegated role name is required.',
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
                errorMessage: 'Justification is required to add a role.',
            });
            return;
        }

        this.api
            .listRoles(this.props.domain)
            .then((roles) => {
                if (roles.includes(roleName)) {
                    this.setState({
                        errorMessage:
                            'Role already exists. Please click on Cancel and use the drop down to select the role.',
                    });
                    return;
                }
                let auditRef = this.state.justification
                    ? this.state.justification
                    : ''; // no UX for this
                this.api
                    .addRole(
                        this.props.domain,
                        roleName,
                        role,
                        auditRef,
                        this.props._csrf
                    )
                    .then(() => {
                        this.props.onSubmit(
                            `Successfully created role ${roleName}`
                        );
                    })
                    .catch((err) => {
                        let message = '';
                        if (err.statusCode === 0) {
                            message = 'Okta expired. Please refresh the page';
                        } else {
                            message = `Status: ${err.statusCode}. Message: ${err.body.message}`;
                        }
                        this.setState({
                            errorMessage: message,
                        });
                    });
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    render() {
        let memberNameChanged = this.inputChanged.bind(this, 'newMemberName');
        let memberDateChanged = this.inputChanged.bind(this, 'newMemberDate');
        let nameChanged = this.inputChanged.bind(this, 'name');

        let members = this.state.members
            ? this.state.members.map((item, idx) => {
                  // dummy place holder so that it can be be used in the form
                  item.approved = true;
                  let remove = this.deleteMember.bind(this, idx);
                  return (
                      <RoleMember
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
                    <StyledInputLabel>Role Category</StyledInputLabel>
                    <StyledButtonGroup
                        buttons={CATEGORIES}
                        selectedName={this.state.category}
                        onClick={this.categoryChanged}
                        noanim
                    />
                </SectionDiv>
                <SectionDiv>
                    <StyledInputLabel>Role Name</StyledInputLabel>
                    <ContentDiv>
                        <StyledInput
                            placeholder='Enter New Role Name'
                            value={this.state.name}
                            onChange={nameChanged}
                            noanim
                            fluid
                        />
                    </ContentDiv>
                </SectionDiv>
                {this.state.category === 'regular' && (
                    <SectionDiv>
                        <StyledInputLabel>Add Member(s)</StyledInputLabel>
                        <ContentDiv>
                            <AddMemberDiv>
                                <StyledInputUser
                                    placeholder='user.<userid> or <domain>.<service>'
                                    value={this.state.newMemberName}
                                    onChange={memberNameChanged}
                                    noanim
                                    fluid
                                />
                                <FlatPickrStyled>
                                    <Flatpicker
                                        onChange={memberDateChanged}
                                        clear={this.state.newMemberDate}
                                        id='addrole'
                                    />
                                </FlatPickrStyled>
                                <ButtonDiv>
                                    <StyledButton onClick={this.addMember}>
                                        Add
                                    </StyledButton>
                                </ButtonDiv>
                            </AddMemberDiv>
                        </ContentDiv>
                    </SectionDiv>
                )}
                {this.state.category === 'regular' && (
                    <SectionDiv>
                        <StyledInputLabel />
                        <StyledIncludedMembersDiv>
                            {members}
                        </StyledIncludedMembersDiv>
                    </SectionDiv>
                )}
                {this.state.category === 'delegated' && (
                    <SectionDiv>
                        <StyledInputLabel>
                            Delegated to ( Domain )
                        </StyledInputLabel>
                        <ContentDiv>
                            <StyledInput
                                placeholder='Enter Domain for Delegate Role'
                                value={this.state.trustDomain}
                                onChange={this.delegateChanged}
                                noanim
                                fluid
                            />
                        </ContentDiv>
                    </SectionDiv>
                )}
                {this.getJustification()}
            </SectionsDiv>
        );
        return (
            <AddModal
                isOpen={this.props.showAddRole}
                cancel={this.props.onCancel}
                submit={this.onSubmit}
                title={`Add Role to ${this.props.domain}`}
                errorMessage={this.state.errorMessage}
                sections={sections}
            />
        );
    }
}
