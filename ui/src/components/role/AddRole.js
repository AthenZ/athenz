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
import AddRoleAdvancedSettings from './AddRoleAdvancedSettings';
import Button from '../denali/Button';
import ButtonGroup from '../denali/ButtonGroup';
import Input from '../denali/Input';
import InputLabel from '../denali/InputLabel';
import Member from '../member/Member';
import styled from '@emotion/styled';
import Flatpicker from '../flatpicker/FlatPicker';
import { colors } from '../denali/styles';
import AddModal from '../modal/AddModal';
import DateUtils from '../utils/DateUtils';
import Icon from '../denali/icons/Icon';
import {
    ADD_ROLE_AUDIT_ENABLED_TOOLTIP,
    ADD_ROLE_AUTHORITY_ROLE_NAME_PLACEHOLDER,
    ADD_ROLE_DELEGATED_DOMAIN_PLACEHOLDER,
    ADD_ROLE_JUSTIFICATION_PLACEHOLDER,
    ADD_ROLE_MEMBER_PLACEHOLDER,
    ADD_ROLE_REMINDER_PLACEHOLDER,
    ADD_ROLE_REVIEW_ENABLED_TOOLTIP,
} from '../constants/constants';
import { addRole } from '../../redux/thunks/roles';
import { connect } from 'react-redux';
import { selectDomainAuditEnabled } from '../../redux/selectors/domainData';
import {
    selectAuthorityAttributes,
    selectUserLink,
} from '../../redux/selectors/domains';
import produce from 'immer';
import InputDropdown from '../denali/InputDropdown';
import MemberUtils from '../utils/MemberUtils';
import { selectAllUsers } from '../../redux/selectors/user';

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
    width: 17%;
`;

const StyledButtonGroup = styled(ButtonGroup)`
    height: 40px;
    width: 200px;
`;

const StyledInput = styled(Input)`
    width: 100%;
`;

const StyledInputAutoComplete = styled(InputDropdown)`
    width: 100%;
`;

const ContentDiv = styled.div`
    flex: 1 1;
    margin-right: 10px;
`;

const AdvancedSettingsDiv = styled.div`
    flex: 1 1;
    margin-left: 10px;
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

const ButtonDiv = styled.div`
    margin-left: 10px;
`;

const StyledButton = styled(Button)`
    width: 125px;
`;

const StyleTable = styled.table`
    width: 100%;
    border-spacing: 0 20px;
    display: table;
    border-collapse: separate;
    border-color: grey;
`;

class AddRole extends React.Component {
    constructor(props) {
        super(props);
        this.categoryChanged = this.categoryChanged.bind(this);
        this.addMember = this.addMember.bind(this);
        this.delegateChanged = this.delegateChanged.bind(this);
        this.onSubmit = this.onSubmit.bind(this);
        this.expandSettings = this.expandSettings.bind(this);
        this.toggleAuditEnabled = this.toggleAuditEnabled.bind(this);
        this.userSearch = this.userSearch.bind(this);
        this.dateUtils = new DateUtils();

        let role = {
            auditEnabled: false,
        };

        this.state = {
            saving: 'nope',
            category: 'regular',
            name: '',
            newMemberName: '',
            memberExpiry: '',
            memberReviewReminder: '',
            members: [],
            trustDomain: '',
            date: '',
            showSettings: false,
            role: role,
        };
    }

    toggleAuditEnabled() {
        let newRole = produce(this.state.role, (draft) => {
            draft.auditEnabled = !this.state.role.auditEnabled;
        });

        this.setState({
            role: newRole,
        });
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

    advancedSettingsChanged(name, val) {
        let role = this.state.role;
        role[name] = val;

        this.setState({
            role: role,
        });
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
                            placeholder={ADD_ROLE_JUSTIFICATION_PLACEHOLDER}
                        />
                    </ContentDiv>
                </SectionDiv>
            );
        }
    }

    addMember() {
        let name = this.state.newMemberName;
        let expirationDate =
            this.state.memberExpiry && this.state.memberExpiry.length > 0
                ? this.state.memberExpiry
                : '';
        let reviewReminderDate =
            this.state.memberReviewReminder &&
            this.state.memberReviewReminder.length > 0
                ? this.state.memberReviewReminder
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
                expiration: expirationDate
                    ? this.dateUtils.uxDatetimeToRDLTimestamp(expirationDate)
                    : '',
                reviewReminder: reviewReminderDate
                    ? this.dateUtils.uxDatetimeToRDLTimestamp(
                          reviewReminderDate
                      )
                    : '',
            });
        }

        this.setState({
            members,
            newMemberName: '',
            memberExpiry: '',
            memberReviewReminder: '',
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

        let role = produce(this.state.role, (draft) => {
            draft.name = roleName;
            draft.reviewEnabled = this.state.reviewEnabled;
            draft.auditEnabled = this.state.role.auditEnabled;
            draft.deleteProtection = this.state.deleteProtection;

            // Add members to role only if role isn't review enabled.
            // If it is - we want all added members to be reviewed including the first members
            if (
                this.state.category === 'regular' &&
                !this.state.reviewEnabled &&
                !this.state.role.auditEnabled
            ) {
                draft.roleMembers =
                    this.state.members.filter((member) => {
                        return member != null || member != undefined;
                    }) || [];
                if (
                    this.state.newMemberName &&
                    this.state.newMemberName !== ''
                ) {
                    draft.roleMembers.push({
                        memberName: this.state.newMemberName,
                        expiration: this.dateUtils.uxDatetimeToRDLTimestamp(
                            this.state.memberExpiry
                        ),
                        reviewReminder: this.dateUtils.uxDatetimeToRDLTimestamp(
                            this.state.memberReviewReminder
                        ),
                    });
                }
            }

            if (this.state.category === 'delegated') {
                draft.trust = this.state.trustDomain;
            }
        });
        if (this.state.category === 'delegated') {
            if (!role.trust) {
                this.setState({
                    errorMessage: 'Delegated role name is required.',
                });
                return;
            }
        }

        if (
            this.props.isDomainAuditEnabled &&
            (this.state.justification === undefined ||
                this.state.justification.trim() === '')
        ) {
            this.setState({
                errorMessage: 'Justification is required to add a role.',
            });
            return;
        }
        let auditRef = this.state.justification ? this.state.justification : ''; // no UX for this

        this.props
            .addRole(roleName, auditRef, role, this.props._csrf, false)
            .then(() =>
                this.props.onSubmit(`${this.props.domain}-${roleName}`, false)
            )
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

    expandSettings() {
        let showSettings = this.state.showSettings;
        this.setState({
            showSettings: !showSettings,
        });
    }

    userSearch(part) {
        return MemberUtils.userSearch(part, this.props.userList);
    }

    render() {
        let memberExpiryDateChanged = this.inputChanged.bind(
            this,
            'memberExpiry'
        );
        let memberReviewReminderDateChanged = this.inputChanged.bind(
            this,
            'memberReviewReminder'
        );
        let nameChanged = this.inputChanged.bind(this, 'name');
        let advancedSettingsChanged = this.advancedSettingsChanged.bind(this);
        let reviewEnabledChanged = this.inputChanged.bind(this);
        let deleteProtectionChanged = this.inputChanged.bind(this);
        let members = this.state.members
            ? this.state.members.map((item, idx) => {
                  // dummy place holder so that it can be be used in the form
                  let member = { ...item };
                  member.approved = true;
                  // item.approved = true;
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
        const arrowup = 'arrowhead-up-circle-solid';
        const arrowdown = 'arrowhead-down-circle';
        let reviewToolTip =
            this.state.reviewEnabled || this.state.role.auditEnabled
                ? ADD_ROLE_REVIEW_ENABLED_TOOLTIP +
                  '\n' +
                  ADD_ROLE_AUDIT_ENABLED_TOOLTIP
                : null;
        let reviewTriggerStyle =
            this.state.reviewEnabled || this.state.role.auditEnabled
                ? { pointerEvents: 'none', opacity: '0.4' }
                : {};
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
                            id={'role-name-input'}
                            placeholder={
                                ADD_ROLE_AUTHORITY_ROLE_NAME_PLACEHOLDER
                            }
                            value={this.state.name}
                            onChange={nameChanged}
                            noanim
                            fluid
                        />
                    </ContentDiv>
                </SectionDiv>
                {this.state.category === 'regular' && (
                    <SectionDiv title={reviewToolTip}>
                        <StyledInputLabel style={reviewTriggerStyle}>
                            Add Member(s)
                        </StyledInputLabel>
                        <ContentDiv style={reviewTriggerStyle}>
                            <AddMemberDiv>
                                <StyledInputAutoComplete
                                    placeholder={ADD_ROLE_MEMBER_PLACEHOLDER}
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
                            </AddMemberDiv>
                        </ContentDiv>
                    </SectionDiv>
                )}
                {this.state.category === 'regular' && (
                    <SectionDiv title={reviewToolTip}>
                        <StyledInputLabel style={reviewTriggerStyle} />
                        <FlatPickrStyled style={reviewTriggerStyle}>
                            <Flatpicker
                                onChange={memberExpiryDateChanged}
                                clear={this.state.memberExpiry}
                                id='addrole'
                            />
                        </FlatPickrStyled>
                        <FlatPickrStyled style={reviewTriggerStyle}>
                            <Flatpicker
                                onChange={memberReviewReminderDateChanged}
                                clear={this.state.memberReviewReminder}
                                id='addrole-reminder'
                                placeholder={ADD_ROLE_REMINDER_PLACEHOLDER}
                            />
                        </FlatPickrStyled>
                    </SectionDiv>
                )}
                {this.state.category === 'regular' && (
                    <SectionDiv title={reviewToolTip}>
                        <StyledInputLabel style={reviewTriggerStyle} />
                        <ButtonDiv style={reviewTriggerStyle}>
                            <StyledButton
                                secondary
                                size={'small'}
                                onClick={this.addMember}
                            >
                                Add
                            </StyledButton>
                        </ButtonDiv>
                    </SectionDiv>
                )}
                {this.state.category === 'regular' && (
                    <SectionDiv title={reviewToolTip}>
                        <StyledInputLabel style={reviewTriggerStyle} />
                        <StyledIncludedMembersDiv style={reviewTriggerStyle}>
                            {members}
                        </StyledIncludedMembersDiv>
                    </SectionDiv>
                )}

                {this.state.category === 'delegated' && (
                    <SectionDiv>
                        <StyledInputLabel>Delegated to</StyledInputLabel>
                        <ContentDiv>
                            <StyledInput
                                placeholder={
                                    ADD_ROLE_DELEGATED_DOMAIN_PLACEHOLDER
                                }
                                value={this.state.trustDomain}
                                onChange={this.delegateChanged}
                                noanim
                                fluid
                            />
                        </ContentDiv>
                    </SectionDiv>
                )}
                {this.getJustification()}
                <SectionDiv>
                    <Icon
                        id={'advanced-settings-icon'}
                        icon={this.state.showSettings ? arrowup : arrowdown}
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
                            <AddRoleAdvancedSettings
                                userAuthorityAttributes={
                                    this.props.userAuthorityAttributes
                                }
                                userProfileLink={this.props.userProfileLink}
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
                                role={this.state.role}
                                reviewEnabled={this.state.reviewEnabled}
                            />
                        </tbody>
                    </StyleTable>
                )}
            </SectionsDiv>
        );
        return (
            <div data-testid='add-role'>
                <AddModal
                    isOpen={this.props.showAddRole}
                    cancel={this.props.onCancel}
                    submit={this.onSubmit}
                    title={`Add Role to ${this.props.domain}`}
                    errorMessage={this.state.errorMessage}
                    sections={sections}
                    overflowY={'auto'}
                />
            </div>
        );
    }
}

const mapStateToProps = (state, props) => {
    return {
        ...props,
        isDomainAuditEnabled: selectDomainAuditEnabled(state),
        userProfileLink: selectUserLink(state),
        userAuthorityAttributes: selectAuthorityAttributes(state),
        userList: selectAllUsers(state),
    };
};

const mapDispatchToProps = (dispatch) => ({
    addRole: (roleName, auditRef, role, _csrf, overrideIfExists) =>
        dispatch(addRole(roleName, auditRef, role, _csrf, overrideIfExists)),
});

export default connect(mapStateToProps, mapDispatchToProps)(AddRole);
