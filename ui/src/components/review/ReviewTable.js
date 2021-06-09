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
import styled from '@emotion/styled';
import ReviewRow from './ReviewRow';
import Button from '../denali/Button';
import Color from '../denali/Color';
import InputLabel from '../denali/InputLabel';
import Input from '../denali/Input';
import RequestUtils from '../utils/RequestUtils';
import { withRouter } from 'next/router';

const TitleDiv = styled.div`
    font-size: 16px;
    font-weight: 600;
`;

const ReviewMembersContainerDiv = styled.div`
    margin: 0;
`;

const ReviewMembersSectionDiv = styled.div`
    margin: 20px;
`;

const ReviewMembersTable = styled.table`
    width: 100%;
    border-spacing: 0 15px;
    display: table;
    border-collapse: separate;
    border-color: grey;
    table-layout: fixed;
`;

const TableHeadStyled = styled.th`
    text-align: ${(props) => props.align};
    border-bottom: 2px solid #d5d5d5;
    color: #9a9a9a;
    font-weight: 600;
    font-size: 0.8rem;
    padding-bottom: 5px;
    vertical-align: top;
    text-transform: uppercase;
    padding: 5px 0 5px 15px;
    word-break: break-all;
`;

const SubmitDiv = styled.div`
    margin-top: 10px;
`;

const SubmitTextSpan = styled.span`
    color: #9a9a9a;
`;

const StyledInputLabel = styled(InputLabel)`
    flex: 0 0 100px;
    margin-right: 2%;
`;

const StyledInput = styled(Input)`
    width: 500px;
`;

const ContentDiv = styled.div`
    flex: 1 1;
    margin-right: 10px;
`;

const StyledAnchor = styled.a`
    color: #3570f4;
    text-decoration: none;
    cursor: pointer;
`;

const StyledJustification = styled(Input)`
    width: 300px;
    margin-top: 5px;
`;

class ReviewTable extends React.Component {
    constructor(props) {
        super(props);
        this.api = this.props.api;
        this.submitReview = this.submitReview.bind(this);
        this.submitRoleMetaExpiry = this.submitRoleMetaExpiry.bind(this);
        this.onClickSettings = this.onClickSettings.bind(this);
        this.cancelRoleMetaUpdate = this.cancelRoleMetaUpdate.bind(this);
        this.onUpdate = this.onUpdate.bind(this);

        let members = props.members && props.members.map((m) => m.memberName);
        this.state = {
            roleObj: props.roleDetails,
            list: props.members || [],
            submittedReview: false,
            extendedMembers: new Set(members),
            deletedMembers: new Set(),
        };
    }

    loadRole() {
        if (this.props.roleDetails.trust) {
            this.props.api
                .getRole(this.props.domain, this.props.role, false, true, false)
                .then((role) => {
                    if (role.trust != null) {
                        this.setState({
                            showTrustError: true,
                            errorMessage: `This is a delegated role. It needs to be reviewed in ${role.trust} domain.`,
                        });
                    } else {
                        let members =
                            role.roleMembers &&
                            role.roleMembers.map((m) => m.memberName);
                        this.setState({
                            roleObj: role,
                            list: role.roleMembers || [],
                            extendedMembers: new Set(members),
                            deletedMembers: new Set(),
                            submittedReview: false,
                        });
                    }
                })
                .catch((err) => {
                    this.setState({
                        errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                    });
                });
        } else {
            this.props.api
                .getRole(
                    this.props.domain,
                    this.props.role,
                    false,
                    false,
                    false
                )
                .then((role) => {
                    if (role.trust != null) {
                        this.setState({
                            showTrustError: true,
                            errorMessage: `This is a delegated role. It needs to be reviewed in ${role.trust} domain.`,
                        });
                    } else {
                        let members =
                            role.roleMembers &&
                            role.roleMembers.map((m) => m.memberName);
                        this.setState({
                            roleObj: role,
                            list: role.roleMembers || [],
                            extendedMembers: new Set(members),
                            deletedMembers: new Set(),
                            submittedReview: false,
                        });
                    }
                })
                .catch((err) => {
                    this.setState({
                        errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                    });
                });
        }
    }

    inputChanged(key, evt) {
        this.setState({ [key]: evt.target.value });
    }

    submitRoleMetaExpiry() {
        let roleMeta = {
            selfServe: this.state.roleObj.selfServe,
            reviewEnabled: this.state.roleObj.reviewEnabled,
        };
        this.props.api
            .putRoleMeta(
                this.props.domain,
                this.props.role,
                roleMeta,
                'Added using Athenz UI',
                this.props._csrf
            )
            .then(() => {
                this.loadRole();
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    submitReview() {
        if (
            this.state.roleObj.roleMembers &&
            this.state.roleObj.roleMembers.length > 0
        ) {
            if (
                this.state.justification === undefined ||
                this.state.justification.trim() === ''
            ) {
                this.setState({
                    errorMessage:
                        'Justification is required to submit the review.',
                });
                return;
            }

            //construct role object from state
            let role = {
                name: this.props.role,
            };
            role.roleMembers = this.state.roleObj.roleMembers;
            role.roleMembers.forEach((m) => {
                if (this.state.deletedMembers.has(m.memberName)) {
                    m.active = false;
                }
                m.expiration = null;
                m.reviewReminder = null;
                delete m.memberFullName; // memberFullName is not a valid property on the server
            });
            role.roleMembers = role.roleMembers.filter((m) => {
                if (
                    this.state.deletedMembers.has(m.memberName) ||
                    this.state.extendedMembers.has(m.memberName)
                ) {
                    return m;
                }
            });
            this.props.api
                .reviewRole(
                    this.props.domain,
                    this.props.role,
                    role,
                    this.state.justification,
                    this.props._csrf
                )
                .then(() => {
                    this.setState({
                        submittedReview: true,
                        errorMessage: null,
                    });
                    this.props.onUpdateSuccess(
                        `Successfully submitted the review for role ${this.props.role}`
                    );
                    this.loadRole();
                })
                .catch((err) => {
                    this.setState({
                        errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                    });
                });
        } else {
            this.props.onUpdateSuccess('There is nothing to review.');
        }
    }

    onClickSettings() {
        this.props.router.push(
            `/domain/${this.props.domain}/role/${this.props.role}/settings`,
            `/domain/${this.props.domain}/role/${this.props.role}/settings`,
            { getInitialProps: true }
        );
    }

    cancelRoleMetaUpdate() {}

    onUpdate(key, value) {
        switch (key) {
            case 'delete':
                this.state.deletedMembers.add(value);
                this.state.extendedMembers.delete(value);
                break;
            case 'extend':
                this.state.extendedMembers.add(value);
                this.state.deletedMembers.delete(value);
                break;
            case 'no-action':
                this.state.extendedMembers.delete(value);
                this.state.deletedMembers.delete(value);
                break;
        }
    }

    getDefaultExpiryText() {
        let text = 'Current default settings are - ';
        let noDaysConfigured = true;
        if (this.state.roleObj && this.state.roleObj.memberExpiryDays) {
            text =
                text +
                'Member Expiry: ' +
                this.state.roleObj.memberExpiryDays +
                ' days. ';
            noDaysConfigured = false;
        }
        if (this.state.roleObj && this.state.roleObj.serviceExpiryDays) {
            text =
                text +
                'Service Expiry: ' +
                this.state.roleObj.serviceExpiryDays +
                ' days. ';
            noDaysConfigured = false;
        }
        if (this.state.roleObj && this.state.roleObj.groupExpiryDays) {
            text =
                text +
                'Group Expiry: ' +
                this.state.roleObj.groupExpiryDays +
                ' days. ';
            noDaysConfigured = false;
        }
        if (this.state.roleObj && this.state.roleObj.memberReviewDays) {
            text =
                text +
                'Member Review: ' +
                this.state.roleObj.memberReviewDays +
                ' days. ';
            noDaysConfigured = false;
        }
        if (this.state.roleObj && this.state.roleObj.serviceReviewDays) {
            text =
                text +
                'Service Review: ' +
                this.state.roleObj.serviceReviewDays +
                ' days. ';
            noDaysConfigured = false;
        }
        if (this.state.roleObj && this.state.roleObj.groupReviewDays) {
            text =
                text +
                'Group Review: ' +
                this.state.roleObj.groupReviewDays +
                ' days. ';
            noDaysConfigured = false;
        }
        if (noDaysConfigured) {
            text = text + 'None';
        }

        const changeText = 'To change it, please click ';

        return (
            <SubmitTextSpan>
                {text}
                <br />
                {changeText}
                <StyledAnchor onClick={this.onClickSettings}>
                    {' '}
                    here{' '}
                </StyledAnchor>
            </SubmitTextSpan>
        );
    }

    render() {
        const left = 'left';
        let center = 'center';
        const rows =
            this.state.list && this.state.list.length > 0
                ? this.state.list
                      .sort((a, b) => {
                          return a.memberName.localeCompare(b.memberName);
                      })
                      .map((item, i) => {
                          let color = 'white';
                          return (
                              <ReviewRow
                                  category={'role'}
                                  key={'role-review-' + i}
                                  idx={'role-review-' + i}
                                  details={item}
                                  role={this.props.role}
                                  color={color}
                                  onUpdate={this.onUpdate}
                                  submittedReview={this.state.submittedReview}
                              />
                          );
                      })
                : [];

        if (this.state.showTrustError) {
            return (
                <ReviewMembersContainerDiv>
                    <ContentDiv>
                        {this.state.errorMessage && (
                            <Color name={'red600'}>
                                {this.state.errorMessage}
                            </Color>
                        )}
                    </ContentDiv>
                </ReviewMembersContainerDiv>
            );
        }

        if (!this.state.list || this.state.list.length === 0) {
            return (
                <ReviewMembersContainerDiv>
                    There is no members to review for role: {this.props.role}.
                </ReviewMembersContainerDiv>
            );
        }

        return (
            <ReviewMembersContainerDiv>
                <TitleDiv>REVIEW EXPIRING MEMBERS</TitleDiv>
                <ReviewMembersSectionDiv data-testid='review-table'>
                    <ReviewMembersTable>
                        <thead>
                            <tr>
                                <TableHeadStyled align={left}>
                                    MEMBER
                                </TableHeadStyled>
                                <TableHeadStyled align={left}>
                                    MEMBER NAME
                                </TableHeadStyled>
                                <TableHeadStyled align={left}>
                                    EXPIRATION DATE
                                </TableHeadStyled>
                                <TableHeadStyled align={left}>
                                    REVIEW REMINDER DATE
                                </TableHeadStyled>
                                <TableHeadStyled align={center}>
                                    EXTEND
                                </TableHeadStyled>
                                <TableHeadStyled align={center}>
                                    NO ACTION
                                </TableHeadStyled>
                                <TableHeadStyled align={center}>
                                    DELETE
                                </TableHeadStyled>
                            </tr>
                        </thead>
                        <tbody>
                            {rows}
                            <tr key='submit-review'>
                                <td colSpan={2}>
                                    <StyledJustification
                                        id='justification'
                                        name='justification'
                                        value={
                                            this.state.justification
                                                ? this.state.justification
                                                : ''
                                        }
                                        onChange={this.inputChanged.bind(
                                            this,
                                            'justification'
                                        )}
                                        autoComplete={'off'}
                                        placeholder='Enter justification here'
                                    />
                                </td>
                                <td colSpan={1}>
                                    <SubmitDiv>
                                        <Button
                                            secondary={true}
                                            onClick={this.submitReview}
                                        >
                                            Submit Review
                                        </Button>
                                    </SubmitDiv>
                                </td>
                                <td colSpan={3}>
                                    {this.getDefaultExpiryText()}
                                </td>
                            </tr>
                            <tr key='error-message'>
                                <td colSpan={6}>
                                    {this.state.errorMessage && (
                                        <Color name={'red600'}>
                                            {this.state.errorMessage}
                                        </Color>
                                    )}
                                </td>
                            </tr>
                        </tbody>
                    </ReviewMembersTable>
                </ReviewMembersSectionDiv>
            </ReviewMembersContainerDiv>
        );
    }
}
export default withRouter(ReviewTable);
