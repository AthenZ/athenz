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
import Button from '../denali/Button';
import Input from '../denali/Input';
import InputLabel from '../denali/InputLabel';
import Member from '../member/Member';
import styled from '@emotion/styled';
import { colors } from '../denali/styles';
import AddModal from '../modal/AddModal';
import DateUtils from '../utils/DateUtils';
import {
    ADD_GROUP_AUDIT_ENABLED_TOOLTIP,
    GROUP_MEMBER_NAME_REGEX,
    GROUP_MEMBER_PLACEHOLDER,
    GROUP_NAME_REGEX,
} from '../constants/constants';
import MemberUtils from '../utils/MemberUtils';
import RegexUtils from '../utils/RegexUtils';
import { connect } from 'react-redux';
import { addGroup } from '../../redux/thunks/groups';
import Switch from '../denali/Switch';
import { selectDomainAuditEnabled } from '../../redux/selectors/domainData';
import InputDropdown from '../denali/InputDropdown';
import { selectAllUsers } from '../../redux/selectors/user';

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
    width: 17%;
`;

const StyledInputLabelPadding = styled(InputLabel)`
    float: left;
    font-size: 14px;
    font-weight: 700;
    width: 17%;
    padding-top: 5px;
`;

const StyledInput = styled(Input)`
    width: 500px;
`;

const StyledInputAutoComplete = styled(InputDropdown)`
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

const SliderDiv = styled.div`
    vertical-align: middle;
`;

const AuditEnabledLabel = styled.label`
    color: ${colors.grey600};
    margin-left: 5px;
    white-space: nowrap;
    font: 300 14px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
`;

class AddGroup extends React.Component {
    constructor(props) {
        super(props);
        this.addMember = this.addMember.bind(this);
        this.onSubmit = this.onSubmit.bind(this);
        this.toggleAuditEnabled = this.toggleAuditEnabled.bind(this);
        this.userSearch = this.userSearch.bind(this);
        this.dateUtils = new DateUtils();
        this.state = {
            saving: 'nope',
            name: '',
            newMemberName: '',
            members: [],
            justification: '',
            auditEnabled: false,
        };
    }

    toggleAuditEnabled() {
        this.setState({
            auditEnabled: !this.state.auditEnabled,
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
        if (this.props.isDomainAuditEnabled) {
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

        let names = MemberUtils.getUserNames(name, GROUP_MEMBER_NAME_REGEX);
        names.validUsers.forEach((name) => {
            members.push({
                memberName: name,
            });
        });
        if (names.invalidUsers.length !== 0) {
            this.setState({
                members,
                newMemberName: names.invalidUsers.toString(),
                errorMessage:
                    "Member name doesn't match regex: " +
                    GROUP_MEMBER_NAME_REGEX,
            });
        } else {
            this.setState({
                members,
                newMemberName: '',
                errorMessage: '',
            });
        }
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

    onSubmit() {
        let groupName = this.state.name;
        if (!groupName || groupName === '') {
            this.setState({
                errorMessage: 'Group name is required.',
            });
            return;
        }

        if (!RegexUtils.validate(groupName, GROUP_NAME_REGEX)) {
            this.setState({
                errorMessage:
                    "Group name doesn't match regex: " + GROUP_NAME_REGEX,
            });
            return;
        }

        let group = {
            name: groupName,
            auditEnabled: this.state.auditEnabled,
        };
        if (!this.state.auditEnabled) {
            group.groupMembers =
                this.state.members.filter((member) => {
                    return member != null || member != undefined;
                }) || [];

            if (this.state.newMemberName && this.state.newMemberName !== '') {
                let names = MemberUtils.getUserNames(
                    this.state.newMemberName,
                    GROUP_MEMBER_NAME_REGEX
                );
                names.validUsers.forEach((name) => {
                    group.groupMembers.push({
                        memberName: name,
                    });
                });
                if (names.invalidUsers.length !== 0) {
                    this.setState({
                        newMemberName: names.invalidUsers.toString(),
                        errorMessage:
                            "Member name doesn't match regex: " +
                            GROUP_MEMBER_NAME_REGEX,
                    });
                    return;
                }
            }
        }

        if (
            this.props.isDomainAuditEnabled &&
            (this.state.justification === undefined ||
                this.state.justification.trim() === '')
        ) {
            this.setState({
                errorMessage: 'Justification is required to add a group.',
            });
            return;
        }
        let auditRef = this.state.justification ? this.state.justification : ''; // no UX for this

        this.props
            .addGroup(groupName, auditRef, group, this.props._csrf)
            .then(() => {
                this.props.onSubmit(
                    `${this.props.domain}-${groupName}`,
                    groupName,
                    false
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
    }

    userSearch(part) {
        return MemberUtils.userSearch(part, this.props.userList);
    }

    render() {
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
        let auditToolTip = this.state.auditEnabled
            ? ADD_GROUP_AUDIT_ENABLED_TOOLTIP
            : null;
        let auditTriggerStyle = this.state.auditEnabled
            ? { pointerEvents: 'none', opacity: '0.4' }
            : {};
        let sections = (
            <SectionsDiv>
                <SectionDiv>
                    <StyledInputLabel>Group Name</StyledInputLabel>
                    <ContentDiv>
                        <StyledInput
                            id={'group-name-input'}
                            placeholder='Enter New Group Name'
                            value={this.state.name}
                            onChange={nameChanged}
                            noanim
                            fluid
                        />
                    </ContentDiv>
                </SectionDiv>
                {
                    <SectionDiv title={auditToolTip}>
                        <StyledInputLabelPadding style={auditTriggerStyle}>
                            Add Member(s)
                        </StyledInputLabelPadding>
                        <ContentDiv style={auditTriggerStyle}>
                            <AddMemberDiv>
                                <StyledInputAutoComplete
                                    placeholder={GROUP_MEMBER_PLACEHOLDER}
                                    itemToString={(i) =>
                                        i === null ? '' : i.value
                                    }
                                    id='member-name'
                                    name='member-name'
                                    onChange={(evt) =>
                                        this.setState({
                                            ['newMemberName']: evt
                                                ? evt.value
                                                : '',
                                        })
                                    }
                                    asyncSearchFunc={this.userSearch}
                                    noanim={true}
                                    fluid={true}
                                />
                                <ButtonDiv style={auditTriggerStyle}>
                                    <StyledButton
                                        secondary
                                        onClick={this.addMember}
                                    >
                                        Add
                                    </StyledButton>
                                </ButtonDiv>
                            </AddMemberDiv>
                        </ContentDiv>
                    </SectionDiv>
                }
                <SectionDiv title={auditToolTip}>
                    <StyledInputLabel />
                    <StyledIncludedMembersDiv>
                        {members}
                    </StyledIncludedMembersDiv>
                </SectionDiv>
                {this.getJustification()}
                {this.props.isDomainAuditEnabled && (
                    <SectionDiv>
                        <SliderDiv>
                            <Switch
                                checked={this.state.auditEnabled}
                                disabled={members.length > 0}
                                onChange={this.toggleAuditEnabled}
                                name={'auditEnabled'}
                            />
                            <AuditEnabledLabel>Audit Enabled</AuditEnabledLabel>
                        </SliderDiv>
                    </SectionDiv>
                )}
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

const mapStateToProps = (state, props) => {
    return {
        ...props,
        isDomainAuditEnabled: selectDomainAuditEnabled(state),
        userList: selectAllUsers(state),
    };
};

const mapDispatchToProps = (dispatch) => ({
    addGroup: (groupName, auditRef, group, _csrf) =>
        dispatch(addGroup(groupName, auditRef, group, _csrf)),
});

export default connect(mapStateToProps, mapDispatchToProps)(AddGroup);
