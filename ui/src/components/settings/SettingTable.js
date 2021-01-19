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
        this.updateCollectionMeta = this.updateCollectionMeta.bind(this);
        this.onValueChange = this.onValueChange.bind(this);
        this.checkValueChange = this.checkValueChange.bind(this);
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

    componentDidUpdate = (prevProps) => {
        if (
            prevProps.collection !== this.props.collection ||
            prevProps.domain !== this.props.domain ||
            prevProps.collectionDetails !== this.props.collectionDetails
        ) {
            this.setState({
                collectionDetails: this.props.collectionDetails,
            });
        }
    };

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
        this.updateCollectionMeta();
    }

    onClickUpdateCancel() {
        this.setState({
            showSubmit: false,
            errorMessage: null,
        });
    }

    onValueChange(name, val) {
        let valChanged = false;
        switch (name) {
            case 'reviewEnabled':
                this.setState({
                    reviewEnabled: val,
                });
                if (val !== !!this.props.collectionDetails.reviewEnabled) {
                    valChanged = true;
                }
                break;
            case 'selfServe':
                this.setState({
                    selfServe: val,
                });
                if (val !== !!this.props.collectionDetails.selfServe) {
                    valChanged = true;
                }
                break;
            case 'memberExpiryDays':
                this.setState({
                    memberExpiryDays: val,
                });
                if (val !== this.props.collectionDetails.memberExpiryDays) {
                    valChanged = true;
                }
                break;
            case 'serviceExpiryDays':
                this.setState({
                    serviceExpiryDays: val,
                });
                if (val !== this.props.collectionDetails.serviceExpiryDays) {
                    valChanged = true;
                }
                break;
            case 'tokenExpiryMins':
                this.setState({
                    tokenExpiryMins: val,
                });
                if (val !== this.props.collectionDetails.tokenExpiryMins) {
                    valChanged = true;
                }
                break;
            case 'certExpiryMins':
                this.setState({
                    certExpiryMins: val,
                });
                if (val !== this.props.collectionDetails.certExpiryMins) {
                    valChanged = true;
                }
                break;
            case 'groupExpiryDays':
                this.setState({
                    groupExpiryDays: val,
                });
                if (val !== this.props.collectionDetails.groupExpiryDays) {
                    valChanged = true;
                }
                break;
            default:
                break;
        }
        let tempValueChange = this.checkValueChange(name) || valChanged;
        this.setState({
            valueChanged: tempValueChange,
        });
    }

    checkValueChange(name) {
        if (
            name !== 'reviewEnabled' &&
            this.state.reviewEnabled !==
                !!this.props.collectionDetails.reviewEnabled
        ) {
            return true;
        } else if (
            name !== 'selfServe' &&
            this.state.selfServe !== !!this.props.collectionDetails.selfServe
        ) {
            return true;
        } else if (
            name !== 'memberExpiryDays' &&
            this.state.memberExpiryDays !==
                this.props.collectionDetails.memberExpiryDays
        ) {
            return true;
        } else if (
            name !== 'serviceExpiryDays' &&
            this.state.serviceExpiryDays !==
                this.props.collectionDetails.serviceExpiryDays
        ) {
            return true;
        } else if (
            name !== 'tokenExpiryMins' &&
            this.state.tokenExpiryMins !==
                this.props.collectionDetails.tokenExpiryMins
        ) {
            return true;
        } else if (
            name !== 'certExpiryMins' &&
            this.state.certExpiryMins !==
                this.props.collectionDetails.certExpiryMins
        ) {
            return true;
        } else if (
            name !== 'groupExpiryDays' &&
            this.state.groupExpiryDays !==
                this.props.collectionDetails.groupExpiryDays
        ) {
            return true;
        } else {
            return false;
        }
    }

    closeModal() {
        this.setState({
            showSuccess: null,
            errorMessage: null,
        });
    }

    updateCollectionMeta() {
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
                this.props.onSubmit();
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
                    'Are you sure you want to permanently change the setting for ' +
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
            <Button secondary disabled={true}>
                Submit
            </Button>
        );

        let message = this.state.showSuccess ? (
            <Alert
                isOpen={this.state.showSuccess}
                onClose={this.closeModal}
                type='success'
                title='Successfully updated the setting(s)'
            />
        ) : null;

        let reviewDesc =
            'Flag indicates whether or not ' +
            this.props.category +
            ' updates require another review and approval';
        rows.push(
            <StyledSettingRow
                domain={domain}
                name='reviewEnabled'
                label='Review'
                type='switch'
                desc={reviewDesc}
                value={this.state.reviewEnabled}
                api={this.api}
                onValueChange={this.onValueChange}
                _csrf={this.props._csrf}
                justificationRequired={this.props.justificationRequired}
                userProfileLink={this.props.userProfileLink}
            />
        );

        let selfServiceDesc =
            'Flag indicates whether or not ' +
            this.props.category +
            ' allows self service';
        rows.push(
            <StyledSettingRow
                domain={domain}
                name='selfServe'
                label='Self-Service'
                type='switch'
                desc={selfServiceDesc}
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
