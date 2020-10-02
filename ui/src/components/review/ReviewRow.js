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
import RadioButton from '../denali/RadioButton';
import styled from '@emotion/styled';
import UpdateModal from '../modal/UpdateModal';
import DateUtils from '../utils/DateUtils';
import RequestUtils from '../utils/RequestUtils';

const TDStyled = styled.td`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 15px;
    vertical-align: middle;
    word-break: break-all;
`;

const TrStyled = styled.tr`
    box-sizing: border-box;
    margin-top: 10px;
    box-shadow: 0 1px 4px #d9d9d9;
    border: 1px solid #fff;
    -webkit-border-image: none;
    border-image: none;
    -webkit-border-image: initial;
    border-image: initial;
    height: 50px;
`;

const MenuDiv = styled.div`
    padding: 5px 10px;
    background-color: black;
    color: white;
    font-size: 12px;
`;

const LeftSpan = styled.span`
    padding-left: 20px;
`;

export default class ReviewRow extends React.Component {
    constructor(props) {
        super(props);
        this.api = this.props.api;
        this.onSubmitApprove = this.onSubmitApprove.bind(this);
        this.onReviewSubmit = this.onReviewSubmit.bind(this);
        this.onClickApproveCancel = this.onClickApproveCancel.bind(this);
        this.onClickDenyCancel = this.onClickDenyCancel.bind(this);
        this.onApprove = this.onApprove.bind(this);
        this.onDeny = this.onDeny.bind(this);
        this.state = {
            name: this.props.details.memberName,
            showApprove: false,
            showDeny: false,
        };
        this.localDate = new DateUtils();
    }

    onReviewSubmit(message) {
        this.setState({ reviewMembers: false });
        if (message) {
            this.props.onUpdateSuccess(message);
        }
    }

    saveJustification(val) {
        this.setState({ deleteJustification: val });
    }

    onApprove() {
        this.setState({
            showApprove: true,
        });
    }

    onDeny() {
        this.setState({
            showDeny: true,
        });
    }

    onSubmitApprove() {
        if (
            this.props.justificationRequired &&
            (this.state.deleteJustification === undefined ||
                this.state.deleteJustification.trim() === '')
        ) {
            this.setState({
                errorMessage: 'Justification is required to update a role',
            });
            return;
        }

        let membership = {
            memberName: this.state.name,
            approve: true,
            //TODO: add expiration time in table, is this needed in the table?
            expiration: '',
        };

        this.api
            .processPending(
                this.props.domain,
                this.props.role,
                this.state.name,
                'Approve pending members in Athenz UI',
                membership,
                this.props._csrf
            )
            .then(() => {
                this.setState({
                    showSuccess: true,
                    showApprove: false,
                });

                this.props.onUpdateSuccess();
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    onSubmitDeny() {
        if (
            this.props.justificationRequired &&
            (this.state.deleteJustification === undefined ||
                this.state.deleteJustification.trim() === '')
        ) {
            this.setState({
                errorMessage: 'Justification is required to update a role',
            });
            return;
        }

        this.api
            .deletePendingMember(
                this.props.domain,
                this.props.role,
                this.state.name,
                'Deny pending members in Athenz UI',
                this.props._csrf
            )
            .then(() => {
                this.setState({
                    showSuccess: true,
                    showDeny: false,
                });

                this.props.onUpdateSuccess();
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    onClickApproveCancel() {
        this.setState({
            showApprove: false,
            errorMessage: '',
        });
    }

    onClickDenyCancel() {
        this.setState({
            showDeny: false,
            errorMessage: '',
        });
    }

    render() {
        let left = 'left';
        let center = 'center';
        let member = this.props.details;
        let color = this.props.color;
        let idx = this.props.idx;

        let submitApprove = this.onSubmitApprove.bind(this, true);
        let submitDeny = this.onSubmitApprove.bind(this, false);
        let clickApproveCancel = this.onClickApproveCancel.bind(this);
        let clickDenyCancel = this.onClickDenyCancel.bind(this);

        return (
            <TrStyled key={this.state.name} data-testid='member-row'>
                <TDStyled color={color} align={left}>
                    {member.memberName}
                </TDStyled>
                <TDStyled color={color} align={left}>
                    {member.memberFullName}
                </TDStyled>
                <TDStyled color={color} align={left}>
                    {member.reviewReminder
                        ? this.localDate.getLocalDate(
                              member.reviewReminder,
                              'UTC',
                              'UTC'
                          )
                        : 'N/A'}
                </TDStyled>
                <TDStyled color={color} align={left}>
                    {member.reviewLastNotifiedTime
                        ? this.localDate.getLocalDate(
                              member.reviewLastNotifiedTime,
                              'UTC',
                              'UTC'
                          )
                        : 'N/A'}
                </TDStyled>
                <TDStyled color={color} align={center}>
                    <RadioButton
                        name={this.props.role + this.props.idx}
                        value='approve'
                        checked={false}
                        onChange={this.onApprove}
                    />
                </TDStyled>
                <TDStyled color={color} align={center}>
                    <RadioButton
                        name={this.props.role + this.props.idx}
                        value='deny'
                        checked={false}
                        onChange={this.onDeny}
                    />
                </TDStyled>
                {this.state.showApprove ? (
                    <UpdateModal
                        name={this.state.name}
                        isOpen={this.state.showApprove}
                        cancel={clickApproveCancel}
                        submit={submitApprove}
                        key={this.state.name + '-approve'}
                        showJustification={this.props.justificationRequired}
                        message={'Are you sure you want to approve the Member '}
                        onJustification={this.saveJustification}
                        errorMessage={this.state.errorMessage}
                    />
                ) : null}
                {this.state.showDeny ? (
                    <UpdateModal
                        name={this.state.name}
                        isOpen={this.state.showDeny}
                        cancel={clickDenyCancel}
                        submit={submitDeny}
                        key={this.state.name + '-deny'}
                        showJustification={this.props.justificationRequired}
                        message={
                            'Are you sure you want to deny the approval for Member '
                        }
                        onJustification={this.saveJustification}
                        errorMessage={this.state.errorMessage}
                    />
                ) : null}
                {this.state.showSuccess ? (
                    <Alert
                        isOpen={this.state.showSuccess}
                        title={this.state.successMessage}
                        onClose={this.closeModal}
                        type='success'
                        title='Successfuly update the setting'
                    />
                ) : null}
            </TrStyled>
        );
    }
}
