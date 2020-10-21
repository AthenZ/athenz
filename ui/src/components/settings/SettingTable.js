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
import SettingRow from './SettingRow';
import Button from '../denali/Button';
import UpdateModal from '../modal/UpdateModal';
import Alert from '../denali/Alert';
import RequestUtils from '../utils/RequestUtils';

const StyleTable = styled.table`
    width: 100%;
    border-spacing: 0 20px;
    display: table;
    border-collapse: separate;
    border-color: grey;
`;

const StyledSettingRow = styled(SettingRow)`
    box-shadow: 0 50px 20px -50px rgba(0, 0, 0, 0.1),
        0 8px 20px 0 rgba(0, 0, 0, 0.1);
`;

const AddContainerDiv = styled.div`
    padding-bottom: 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-flow: row nowrap;
`;

export default class SettingTable extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.toggleSubmit = this.toggleSubmit.bind(this);
        this.toggleReset = this.toggleReset.bind(this);
        this.onSubmitUpdate = this.onSubmitUpdate.bind(this);
        this.onClickUpdateCancel = this.onClickUpdateCancel.bind(this);
        this.closeModal = this.closeModal.bind(this);
        this.updateRoleMeta = this.updateRoleMeta.bind(this);
        this.onValueChange = this.onValueChange.bind(this);

        this.state = {
            reviewEnabled: !!props.roleDetails.reviewEnabled,
            selfServe: !!props.roleDetails.selfServe,
            memberExpiryDays: props.roleDetails.memberExpiryDays,
            serviceExpiryDays: props.roleDetails.serviceExpiryDays,
            tokenExpiryMins: props.roleDetails.tokenExpiryMins,
            certExpiryMins: props.roleDetails.certExpiryMins,
            signAlgorithm: props.roleDetails.signAlgorithm,
            showSubmit: false,
            showSuccess: false,
            errorMessage: null,
        };
    }

    toggleSubmit() {
        this.setState({
            showSubmit: !this.state.showSubmit,
        });
    }

    toggleReset() {
        console.log('reset');
        this.setState({
            reviewEnabled: !!this.props.roleDetails.reviewEnabled,
            selfServe: !!this.props.roleDetails.selfServe,
            memberExpiryDays: this.props.roleDetails.memberExpiryDays,
            serviceExpiryDays: this.props.roleDetails.serviceExpiryDays,
            tokenExpiryMins: this.props.roleDetails.tokenExpiryMins,
            certExpiryMins: this.props.roleDetails.certExpiryMins,
            signAlgorithm: this.props.roleDetails.signAlgorithm,
            showSubmit: false,
            showSuccess: false,
            errorMessage: null,
        });
    }

    onSubmitUpdate() {
        if (
            this.props.justificationRequired &&
            (this.state.deleteJustification === undefined ||
                this.state.deleteJustification.trim() === '')
        ) {
            this.setState({
                errorMessage: 'Justification is required to update a setting',
            });
            return;
        }
        this.updateRoleMeta();
    }

    onClickUpdateCancel() {
        this.setState({
            showSubmit: false,
        });
    }

    onValueChange(name, val) {
        switch (name) {
            case 'reviewEnabled':
                this.setState({
                    reviewEnabled: val,
                });
                break;
            case 'selfServe':
                this.setState({
                    selfServe: val,
                });
                break;
            case 'memberExpiryDays':
                this.setState({
                    memberExpiryDays: val,
                });
                break;
            case 'serviceExpiryDays':
                this.setState({
                    serviceExpiryDays: val,
                });
                break;
            case 'tokenExpiryMins':
                this.setState({
                    tokenExpiryMins: val,
                });
                break;
            case 'certExpiryMins':
                this.setState({
                    certExpiryMins: val,
                });
                break;
            case 'signAlgorithm':
                this.setState({
                    signAlgorithm: val,
                });
                break;
            default:
                break;
        }
    }

    closeModal() {
        this.setState({
            showSuccess: null,
        });
    }

    updateRoleMeta() {
        let roleMeta = {};

        roleMeta.reviewEnabled = this.state.reviewEnabled;
        roleMeta.selfServe = this.state.selfServe;
        roleMeta.memberExpiryDays = this.state.memberExpiryDays;
        roleMeta.serviceExpiryDays = this.state.serviceExpiryDays;
        roleMeta.tokenExpiryMins = this.state.tokenExpiryMins;
        roleMeta.certExpiryMins = this.state.certExpiryMins;
        roleMeta.signAlgorithm = this.state.signAlgorithm;

        this.api
            .putRoleMeta(
                this.props.domain,
                this.props.role,
                roleMeta,
                'Updated Role Meta using Athenz UI',
                this.props._csrf
            )
            .then(() => {
                this.setState({
                    showSuccess: true,
                    showSubmit: false,
                });
                window.location.reload();
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    render() {
        const { domain, role, roleDetails } = this.props;
        let rows = [];

        let submitSettings = this.state.showSubmit ? (
            <UpdateModal
                name={role}
                isOpen={this.state.showSubmit}
                cancel={this.onClickUpdateCancel}
                submit={this.onSubmitUpdate}
                key={this.state.updateName + '-update'}
                message={
                    'Are you sure you want to permanently change the setting for role '
                }
                showJustification={this.state.justificationRequired}
                onJustification={this.saveJustification}
                errorMessage={this.state.errorMessage}
            />
        ) : (
            ''
        );

        let message = this.state.showSuccess ? (
            <Alert
                isOpen={this.state.showSuccess}
                onClose={this.closeModal}
                type='success'
                title='Successfuly update the setting'
            />
        ) : null;

        rows.push(
            <StyledSettingRow
                domain={domain}
                role={role}
                roleDetails={roleDetails}
                name='reviewEnabled'
                label='Review'
                type='switch'
                desc='Flag indicates whether or not role updates require another review and approval'
                value={this.state.reviewEnabled}
                api={this.api}
                onValueChange={this.onValueChange}
                _csrf={this.props._csrf}
                justificationRequired={this.props.justificationRequired}
                userProfileLink={this.props.userProfileLink}
            />
        );

        rows.push(
            <StyledSettingRow
                domain={domain}
                role={role}
                roleDetails={roleDetails}
                name='selfServe'
                label='Self-Service'
                type='switch'
                desc='Flag indicates whether or not role allows self service'
                value={this.state.selfServe}
                api={this.api}
                onValueChange={this.onValueChange}
                _csrf={this.props._csrf}
                justificationRequired={this.props.justificationRequired}
                userProfileLink={this.props.userProfileLink}
            />
        );

        rows.push(
            <StyledSettingRow
                domain={domain}
                role={role}
                roleDetails={roleDetails}
                name='memberExpiryDays'
                label='Member Expiry'
                type='input'
                desc='All user members in the role will have specified max expiry days'
                unit='Days'
                value={this.state.memberExpiryDays}
                api={this.api}
                onValueChange={this.onValueChange}
                _csrf={this.props._csrf}
                justificationRequired={this.props.justificationRequired}
                userProfileLink={this.props.userProfileLink}
            />
        );

        rows.push(
            <StyledSettingRow
                domain={domain}
                role={role}
                roleDetails={roleDetails}
                name='serviceExpiryDays'
                label='Service Expiry'
                type='input'
                unit='Days'
                desc='All services in the role will have specified max expiry days'
                value={this.state.serviceExpiryDays}
                api={this.api}
                onValueChange={this.onValueChange}
                _csrf={this.props._csrf}
                justificationRequired={this.props.justificationRequired}
                userProfileLink={this.props.userProfileLink}
            />
        );

        rows.push(
            <StyledSettingRow
                domain={domain}
                role={role}
                roleDetails={roleDetails}
                name='tokenExpiryMins'
                label='Token Expiry'
                type='input'
                unit='Mins'
                desc='Tokens issued for this role will have specified max timeout in mins'
                value={this.state.tokenExpiryMins}
                api={this.api}
                onValueChange={this.onValueChange}
                _csrf={this.props._csrf}
                justificationRequired={this.props.justificationRequired}
                userProfileLink={this.props.userProfileLink}
            />
        );

        rows.push(
            <StyledSettingRow
                domain={domain}
                role={role}
                roleDetails={roleDetails}
                name='certExpiryMins'
                label='Certificate Expiry'
                type='input'
                unit='Mins'
                desc='Certs issued for this role will have specified max timeout in mins'
                value={this.state.certExpiryMins}
                api={this.api}
                onValueChange={this.onValueChange}
                _csrf={this.props._csrf}
                justificationRequired={this.props.justificationRequired}
                userProfileLink={this.props.userProfileLink}
            />
        );

        rows.push(
            <StyledSettingRow
                domain={domain}
                role={role}
                roleDetails={roleDetails}
                name='signAlgorithm'
                label='Signing Algorithm'
                type='radio'
                desc='RSA or ECDSA signing algorithm to be used for tokens'
                value={this.state.signAlgorithm}
                api={this.api}
                onValueChange={this.onValueChange}
                _csrf={this.props._csrf}
                justificationRequired={this.props.justificationRequired}
                userProfileLink={this.props.userProfileLink}
            />
        );

        rows.push(
            <AddContainerDiv>
                <div>
                    <Button secondary onClick={this.toggleSubmit}>
                        Submit
                    </Button>
                    {submitSettings}
                    <Button secondary onClick={this.toggleReset}>
                        Reset
                    </Button>
                    {message}
                </div>
            </AddContainerDiv>
        );

        return <StyleTable data-testid='setting-table'>{rows}</StyleTable>;
    }
}
