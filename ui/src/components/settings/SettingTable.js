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
            reviewEnabled: !!props.collectionDetails.reviewEnabled,
            selfServe: !!props.collectionDetails.selfServe,
            memberExpiryDays: props.collectionDetails.memberExpiryDays,
            groupExpiryDays: props.collectionDetails.groupExpiryDays,
            serviceExpiryDays: props.collectionDetails.serviceExpiryDays,
            tokenExpiryMins: props.collectionDetails.tokenExpiryMins,
            certExpiryMins: props.collectionDetails.certExpiryMins,
            showSubmit: false,
            showSuccess: false,
            errorMessage: null,
            valueChanged: false,
        };
    }

    toggleSubmit() {
        this.setState({
            showSubmit: !this.state.showSubmit,
            valueChanged: false,
        });
    }

    toggleReset() {
        this.setState({
            reviewEnabled: !!this.props.collectionDetails.reviewEnabled,
            selfServe: !!this.props.collectionDetails.selfServe,
            memberExpiryDays:
                this.props.collectionDetails.memberExpiryDays === undefined
                    ? ''
                    : this.props.collectionDetails.memberExpiryDays,
            groupExpiryDays:
                this.props.collectionDetails.groupExpiryDays === undefined
                    ? ''
                    : this.props.collectionDetails.groupExpiryDays,
            serviceExpiryDays:
                this.props.collectionDetails.serviceExpiryDays === undefined
                    ? ''
                    : this.props.collectionDetails.serviceExpiryDays,
            tokenExpiryMins:
                this.props.collectionDetails.tokenExpiryMins === undefined
                    ? ''
                    : this.props.collectionDetails.tokenExpiryMins,
            certExpiryMins:
                this.props.collectionDetails.certExpiryMins === undefined
                    ? ''
                    : this.props.collectionDetails.certExpiryMins,
            showSubmit: false,
            showSuccess: false,
            errorMessage: null,
            valueChanged: false,
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
            errorMessage: null,
        });
    }

    onValueChange(name, val) {
        this.setState({
            valueChanged: true,
        });
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
            case 'groupExpiryDays':
                this.setState({
                    groupExpiryDays: val,
                });
                break;
            default:
                break;
        }
    }

    closeModal() {
        this.setState({
            showSuccess: null,
            errorMessage: null,
        });
    }

    updateRoleMeta() {
        let collectionMeta = {};

        collectionMeta.reviewEnabled = this.state.reviewEnabled;
        collectionMeta.selfServe = this.state.selfServe;
        if (this.props.category === 'role') {
            collectionMeta.memberExpiryDays = this.state.memberExpiryDays;
            collectionMeta.groupExpiryDays = this.state.groupExpiryDays;
            collectionMeta.serviceExpiryDays = this.state.serviceExpiryDays;
            collectionMeta.tokenExpiryMins = this.state.tokenExpiryMins;
            collectionMeta.certExpiryMins = this.state.certExpiryMins;
        }

        this.api
            .putMeta(
                this.props.domain,
                this.props.collection,
                collectionMeta,
                'Updated' + this.props.category + 'Meta using Athenz UI',
                this.props._csrf,
                this.props.category
            )
            .then(() => {
                this.setState({
                    showSuccess: true,
                    showSubmit: false,
                });
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    render() {
        const { domain, collection } = this.props;
        let rows = [];

        let submitSettings = this.state.showSubmit ? (
            <UpdateModal
                name={collection}
                isOpen={this.state.showSubmit}
                cancel={this.onClickUpdateCancel}
                submit={this.onSubmitUpdate}
                key={this.state.updateName + '-update'}
                message={
                    'Are you sure you want to permanently change the setting for' +
                    this.props.category +
                    ' '
                }
                showJustification={this.state.justificationRequired}
                onJustification={this.saveJustification}
                errorMessage={this.state.errorMessage}
            />
        ) : (
            ''
        );

        let submitButton = this.state.valueChanged ? (
            <Button primary onClick={this.toggleSubmit}>
                Submit
            </Button>
        ) : (
            <Button secondary onClick={this.toggleSubmit}>
                Submit
            </Button>
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

        this.props.category === 'role' &&
            rows.push(
                <StyledSettingRow
                    domain={domain}
                    name='memberExpiryDays'
                    label='User Expiry'
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

        this.props.category === 'role' &&
            rows.push(
                <StyledSettingRow
                    domain={domain}
                    name='groupExpiryDays'
                    label='Group Expiry'
                    type='input'
                    desc='All group members in the role will have specified max expiry days'
                    unit='Days'
                    value={this.state.groupExpiryDays}
                    api={this.api}
                    onValueChange={this.onValueChange}
                    _csrf={this.props._csrf}
                    justificationRequired={this.props.justificationRequired}
                    userProfileLink={this.props.userProfileLink}
                />
            );

        this.props.category === 'role' &&
            rows.push(
                <StyledSettingRow
                    domain={domain}
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

        this.props.category === 'role' &&
            rows.push(
                <StyledSettingRow
                    domain={domain}
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

        this.props.category === 'role' &&
            rows.push(
                <StyledSettingRow
                    domain={domain}
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
            <AddContainerDiv>
                <div>
                    {submitButton}
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
