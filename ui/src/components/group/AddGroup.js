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
import Input from '../denali/Input';
import InputLabel from '../denali/InputLabel';
import Member from '../member/Member';
import styled from '@emotion/styled';
import { colors } from '../denali/styles';
import AddModal from '../modal/AddModal';
import DateUtils from '../utils/DateUtils';
import RequestUtils from '../utils/RequestUtils';

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
    width: 17%;
`;

const StyledInput = styled(Input)`
    width: 500px;
`;

const StyledInputUser = styled(Input)`
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
    width: 780px;
    text-align: left;
    background-color: ${colors.white};
`;

const ButtonDiv = styled.div`
    margin-left: 10px;
`;

const StyledButton = styled(Button)`
    width: 125px;
`;

export default class AddGroup extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.addMember = this.addMember.bind(this);
        this.onSubmit = this.onSubmit.bind(this);
        this.dateUtils = new DateUtils();
        this.state = {
            saving: 'nope',
            name: '',
            newMemberName: '',
            members: [],
            justification: '',
        };
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
            });
        }

        this.setState({
            members,
            newMemberName: '',
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

    onSubmit() {
        let groupName = this.state.name;
        if (!groupName || groupName === '') {
            this.setState({
                errorMessage: 'Group name is required.',
            });
            return;
        }

        let group = { name: groupName };
        group.groupMembers =
            this.state.members.filter((member) => {
                return member != null || member != undefined;
            }) || [];
        if (this.state.newMemberName && this.state.newMemberName !== '') {
            let names = (this.state.newMemberName || '')
                .replace(/[\r\n\s]+/g, ',')
                .split(',')
                .map((n) => n.trim())
                .filter((n) => n);

            for (let i = 0; i < names.length; i++) {
                group.groupMembers.push({
                    memberName: names[i],
                });
            }
        }

        if (
            this.props.justificationRequired &&
            (this.state.justification === undefined ||
                this.state.justification.trim() === '')
        ) {
            this.setState({
                errorMessage: 'Justification is required to add a group.',
            });
            return;
        }

        this.api
            .getGroups(this.props.domain)
            .then((groups) => {
                if (groups.includes(groupName)) {
                    this.setState({
                        errorMessage: 'Group already exists.',
                    });
                    return;
                }
                let auditRef = this.state.justification
                    ? this.state.justification
                    : ''; // no UX for this
                this.api
                    .addGroup(
                        this.props.domain,
                        groupName,
                        group,
                        auditRef,
                        this.props._csrf
                    )
                    .then(() => {
                        this.props.onSubmit(
                            `Successfully created group ${groupName}`
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

        let nameChanged = this.inputChanged.bind(this, 'name');

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
                    <StyledInputLabel>Group Name</StyledInputLabel>
                    <ContentDiv>
                        <StyledInput
                            placeholder='Enter New Group Name'
                            value={this.state.name}
                            onChange={nameChanged}
                            noanim
                            fluid
                        />
                    </ContentDiv>
                </SectionDiv>
                {
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
                                <ButtonDiv>
                                    <StyledButton onClick={this.addMember}>
                                        Add
                                    </StyledButton>
                                </ButtonDiv>
                            </AddMemberDiv>
                        </ContentDiv>
                    </SectionDiv>
                }
                <SectionDiv>
                    <StyledInputLabel />
                    <StyledIncludedMembersDiv>
                        {members}
                    </StyledIncludedMembersDiv>
                </SectionDiv>
                {this.getJustification()}
            </SectionsDiv>
        );
        return (
            <div data-testid='add-group'>
                <AddModal
                    isOpen={this.props.showAddGroup}
                    cancel={this.props.onCancel}
                    submit={this.onSubmit}
                    title={`Add Group to ${this.props.domain}`}
                    errorMessage={this.state.errorMessage}
                    sections={sections}
                />
            </div>
        );
    }
}
