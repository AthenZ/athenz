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
import { selectDomainAuditEnabled } from '../../redux/selectors/domainData';
import InputDropdown from '../denali/InputDropdown';
import { selectAllUsers } from '../../redux/selectors/user';
import Flatpicker from '../flatpicker/FlatPicker';
import Icon from '../denali/icons/Icon';
import produce from 'immer';
import AddGroupAdvancedSettings from './AddGroupAdvancedSettings';
import { selectAuthorityAttributes } from '../../redux/selectors/domains';

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
    width: 100%;
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
    width: 700px;
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

const FlatPickrStyled = styled.div`
    flex: 1 1;
    margin-right: 10px;
    & > div input {
        position: relative;
        font: 300 14px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
        background-color: rgba(53, 112, 244, 0.05);
        box-shadow: none;
        color: rgb(48, 48, 48);
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

const AdvancedSettingsDiv = styled.div`
    flex: 1 1;
    margin-left: 10px;
`;

const StyleTable = styled.table`
    width: 100%;
    border-spacing: 0 20px;
    display: table;
    border-collapse: separate;
    border-color: grey;
`;

class AddGroup extends React.Component {
    constructor(props) {
        super(props);
        this.addMember = this.addMember.bind(this);
        this.onSubmit = this.onSubmit.bind(this);
        this.toggleAuditEnabled = this.toggleAuditEnabled.bind(this);
        this.userSearch = this.userSearch.bind(this);
        this.expandSettings = this.expandSettings.bind(this);
        this.dateUtils = new DateUtils();

        const group = {
            auditEnabled: false,
        };

        this.state = {
            saving: 'nope',
            name: '',
            newMemberName: '',
            memberNameInInput: '',
            memberExpiry: '',
            members: [],
            justification: '',
            showSettings: false,
            group,
        };
    }

    toggleAuditEnabled() {
        let newGroup = produce(this.state.group, (draft) => {
            draft.auditEnabled = !this.state.group.auditEnabled;
        });

        this.setState({
            group: newGroup,
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
                expiration: this.dateUtils.uxDatetimeToRDLTimestamp(
                    this.state.memberExpiry
                ),
            });
        });

        if (names.invalidUsers.length) {
            this.setState({
                members,
                newMemberName: names.invalidUsers.toString(),
                memberExpiry: '',
                memberNameInInput: '',
                errorMessage:
                    "Member name doesn't match regex: " +
                    GROUP_MEMBER_NAME_REGEX,
            });
        } else {
            this.setState({
                members,
                newMemberName: '',
                memberExpiry: '',
                memberNameInInput: '',
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

        const validMembers = [];

        if (this.state.newMemberName) {
            let names = MemberUtils.getUserNames(
                this.state.newMemberName,
                GROUP_MEMBER_NAME_REGEX
            );

            names.validUsers.forEach((name) => {
                validMembers.push({
                    memberName: name,
                    expiration: this.dateUtils.uxDatetimeToRDLTimestamp(
                        this.state.memberExpiry
                    ),
                });
            });

            if (names.invalidUsers.length) {
                this.setState({
                    newMemberName: names.invalidUsers.toString(),
                    errorMessage:
                        "Member name doesn't match regex: " +
                        GROUP_MEMBER_NAME_REGEX,
                });
                return;
            }
        }

        let group = produce(this.state.group, (draft) => {
            draft.name = groupName;
            draft.reviewEnabled = this.state.reviewEnabled;
            draft.auditEnabled = this.state.group.auditEnabled;
            draft.deleteProtection = this.state.deleteProtection;

            if (!this.state.reviewEnabled && !this.state.group.auditEnabled) {
                draft.groupMembers = this.state.members.filter(
                    (member) => member
                );
                draft.groupMembers.push(...validMembers);
            }
        });

        if (
            this.state.newMemberName.trim() !==
            this.state.memberNameInInput.trim()
        ) {
            this.setState({
                errorMessage:
                    'Member must be selected in the dropdown or member input field must be empty.',
            });
            return;
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

    onInputValueChange(inputVal) {
        this.setState({ ['memberNameInInput']: inputVal });
        if (this.state.newMemberName && this.state.newMemberName !== inputVal) {
            this.setState({ ['newMemberName']: '' });
        }
    }

    userSearch(part) {
        return MemberUtils.userSearch(part, this.props.userList);
    }

    advancedSettingsChanged(name, val) {
        let newGroup = produce(this.state.group, (draft) => {
            draft[name] = val;
        });

        this.setState({
            group: newGroup,
        });
    }

    expandSettings() {
        this.setState((prevState) => ({
            showSettings: !prevState.showSettings,
        }));
    }

    render() {
        let memberExpiryDateChanged = this.inputChanged.bind(
            this,
            'memberExpiry'
        );

        let nameChanged = this.inputChanged.bind(this, 'name');
        let advancedSettingsChanged = this.advancedSettingsChanged.bind(this);
        let deleteProtectionChanged = this.inputChanged.bind(this);
        let reviewEnabledChanged = this.inputChanged.bind(this);

        const arrowUp = 'arrowhead-up-circle-solid';
        const arrowDown = 'arrowhead-down-circle';

        let members = this.state.members
            ? this.state.members.map((item, idx) => {
                  let member = { ...item };
                  member.approved = true;
                  let remove = this.deleteMember.bind(this, idx);
                  return (
                      <Member
                          key={idx}
                          item={member}
                          onClickRemove={remove}
                          noanim
                      />
                  );
              })
            : '';
        let auditToolTip = this.state.group.auditEnabled
            ? ADD_GROUP_AUDIT_ENABLED_TOOLTIP
            : null;
        let reviewTriggerStyle =
            this.state.reviewEnabled || this.state.group.auditEnabled
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

                <SectionDiv title={auditToolTip}>
                    <StyledInputLabelPadding style={reviewTriggerStyle}>
                        Add Member(s)
                    </StyledInputLabelPadding>

                    <ContentDiv style={reviewTriggerStyle}>
                        <AddMemberDiv>
                            <StyledInputAutoComplete
                                value={this.state.memberNameInInput}
                                selectedDropdownValue={this.state.newMemberName} // marks value in dropdown selected
                                onInputValueChange={(inputVal) => {
                                    this.onInputValueChange(inputVal);
                                }}
                                placeholder={GROUP_MEMBER_PLACEHOLDER}
                                itemToString={(i) =>
                                    i === null ? '' : i.value
                                }
                                id='member-name'
                                name='member-name'
                                onChange={(evt) =>
                                    this.setState({
                                        ['newMemberName']: evt ? evt.value : '',
                                    })
                                }
                                asyncSearchFunc={this.userSearch}
                                noanim={true}
                                fluid={true}
                            />
                        </AddMemberDiv>
                    </ContentDiv>
                </SectionDiv>

                <SectionDiv title={auditToolTip}>
                    <StyledInputLabel style={reviewTriggerStyle} />
                    <FlatPickrStyled style={reviewTriggerStyle}>
                        <Flatpicker
                            onChange={memberExpiryDateChanged}
                            clear={this.state.memberExpiry}
                            id='groupMemberExpiry'
                            data-testid='memberExpiry'
                        />
                    </FlatPickrStyled>
                </SectionDiv>

                <SectionDiv title={auditToolTip}>
                    <StyledInputLabel style={reviewTriggerStyle} />
                    <ButtonDiv style={reviewTriggerStyle}>
                        <StyledButton
                            secondary
                            size={'small'}
                            onClick={this.addMember}
                            data-wdio={'add-group-member'}
                        >
                            Add
                        </StyledButton>
                    </ButtonDiv>
                </SectionDiv>

                <SectionDiv title={auditToolTip}>
                    <StyledInputLabel />
                    <StyledIncludedMembersDiv>
                        {members}
                    </StyledIncludedMembersDiv>
                </SectionDiv>
                {this.getJustification()}

                <SectionDiv>
                    <Icon
                        id={'advanced-settings-icon'}
                        icon={this.state.showSettings ? arrowUp : arrowDown}
                        onClick={this.expandSettings}
                        color={colors.icons}
                        isLink
                        size={'1.25em'}
                        verticalAlign={'text-bottom'}
                    />
                    <AdvancedSettingsDiv>
                        {'Advanced Settings'}
                    </AdvancedSettingsDiv>
                </SectionDiv>

                {this.state.showSettings && (
                    <StyleTable data-testid='advanced-setting-table'>
                        <tbody>
                            <AddGroupAdvancedSettings
                                userAuthorityAttributes={
                                    this.props.userAuthorityAttributes
                                }
                                advancedSettingsChanged={
                                    advancedSettingsChanged
                                }
                                reviewEnabledChanged={reviewEnabledChanged}
                                deleteProtectionChanged={
                                    deleteProtectionChanged
                                }
                                auditEnabledChanged={this.toggleAuditEnabled}
                                isDomainAuditEnabled={
                                    this.props.isDomainAuditEnabled
                                }
                                members={members}
                                group={this.state.group}
                                reviewEnabled={this.state.reviewEnabled}
                            />
                        </tbody>
                    </StyleTable>
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
        userAuthorityAttributes: selectAuthorityAttributes(state),
        userList: selectAllUsers(state),
    };
};

const mapDispatchToProps = (dispatch) => ({
    addGroup: (groupName, auditRef, group, _csrf) =>
        dispatch(addGroup(groupName, auditRef, group, _csrf)),
});

export default connect(mapStateToProps, mapDispatchToProps)(AddGroup);
