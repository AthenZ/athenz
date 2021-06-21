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
import _ from 'lodash';
import { MODAL_TIME_OUT } from '../constants/constants';

const StyleTable = styled.table`
    width: 100%;
    border-spacing: 0 20px;
    display: table;
    border-collapse: separate;
    border-color: grey;
`;

const RolesSectionDiv = styled.div`
    margin: 20px;
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
        this.reloadCollection = this.reloadCollection.bind(this);
        this.onClickUpdateCancel = this.onClickUpdateCancel.bind(this);
        this.closeModal = this.closeModal.bind(this);
        this.updateCollectionMeta = this.updateCollectionMeta.bind(this);
        this.onValueChange = this.onValueChange.bind(this);
        this.setCollectionDetails = this.setCollectionDetails.bind(this);

        let originalCollectionDetails = this.setCollectionDetails(
            this.props.collectionDetails
        );
        let copyCollectionDetails = _.cloneDeep(originalCollectionDetails);

        let boolUserAuthorityAttributes = [];
        let dateUserAuthorityAttributes = [];
        if (
            this.props.userAuthorityAttributes &&
            this.props.userAuthorityAttributes.attributes
        ) {
            let authorityAttributes =
                this.props.userAuthorityAttributes.attributes;
            if (authorityAttributes.bool && authorityAttributes.bool.values) {
                authorityAttributes.bool.values.forEach((attribute) => {
                    boolUserAuthorityAttributes.push({
                        value: attribute,
                        name: attribute,
                    });
                });
            }

            if (authorityAttributes.date && authorityAttributes.date.values) {
                authorityAttributes.date.values.forEach((attribute) => {
                    dateUserAuthorityAttributes.push({
                        value: attribute,
                        name: attribute,
                    });
                });
            }
        }

        this.state = {
            originalCollectionDetails: originalCollectionDetails,
            copyCollectionDetails: copyCollectionDetails,
            showSubmit: false,
            showSuccess: false,
            errorMessage: null,
            enableSubmit: false,
            boolUserAuthorityAttributes: boolUserAuthorityAttributes,
            dateUserAuthorityAttributes: dateUserAuthorityAttributes,
        };
    }

    setCollectionDetails(collection) {
        let collectionDetails = {
            reviewEnabled: !!collection.reviewEnabled,
            selfServe: !!collection.selfServe,
            memberExpiryDays:
                collection.memberExpiryDays === undefined
                    ? ''
                    : collection.memberExpiryDays.toString(),
            memberReviewDays:
                collection.memberReviewDays === undefined
                    ? ''
                    : collection.memberReviewDays.toString(),
            groupExpiryDays:
                collection.groupExpiryDays === undefined
                    ? ''
                    : collection.groupExpiryDays.toString(),
            groupReviewDays:
                collection.groupReviewDays === undefined
                    ? ''
                    : collection.groupReviewDays.toString(),
            serviceExpiryDays:
                collection.serviceExpiryDays === undefined
                    ? ''
                    : collection.serviceExpiryDays.toString(),
            serviceReviewDays:
                collection.serviceReviewDays === undefined
                    ? ''
                    : collection.serviceReviewDays.toString(),
            tokenExpiryMins:
                collection.tokenExpiryMins === undefined
                    ? ''
                    : collection.tokenExpiryMins.toString(),
            certExpiryMins:
                collection.certExpiryMins === undefined
                    ? ''
                    : collection.certExpiryMins.toString(),
            roleCertExpiryMins:
                collection.roleCertExpiryMins === undefined
                    ? ''
                    : collection.roleCertExpiryMins.toString(),
            userAuthorityFilter:
                collection.userAuthorityFilter === undefined
                    ? ''
                    : collection.userAuthorityFilter.toString(),
            userAuthorityExpiration:
                collection.userAuthorityExpiration === undefined
                    ? ''
                    : collection.userAuthorityExpiration.toString(),
        };
        return collectionDetails;
    }

    toggleSubmit() {
        this.setState({
            showSubmit: !this.state.showSubmit,
        });
    }

    toggleReset() {
        this.setState({
            copyCollectionDetails: _.cloneDeep(
                this.state.originalCollectionDetails
            ),
            showSubmit: false,
            showSuccess: false,
            errorMessage: null,
            enableSubmit: false,
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
        let collectionDetails = this.state.copyCollectionDetails;
        collectionDetails[name] = val;

        this.setState({
            copyCollectionDetails: collectionDetails,
            enableSubmit: !_.isEqual(
                this.state.originalCollectionDetails,
                collectionDetails
            ),
        });
    }

    closeModal() {
        this.setState({
            showSuccess: null,
            errorMessage: null,
        });
    }

    reloadCollection() {
        this.api
            .getCollection(
                this.props.domain,
                this.props.collection,
                this.props.category
            )
            .then((collection) => {
                let collectionDetails = this.setCollectionDetails(collection);
                this.setState({
                    originalCollectionDetails: collectionDetails,
                    copyCollectionDetails: _.cloneDeep(collectionDetails),
                    errorMessage: null,
                });
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    updateCollectionMeta() {
        let collectionMeta = {};

        if (this.props.category === 'role') {
            collectionMeta = this.state.copyCollectionDetails;
        } else if (this.props.category === 'group') {
            collectionMeta.reviewEnabled =
                this.state.copyCollectionDetails.reviewEnabled;
            collectionMeta.selfServe =
                this.state.copyCollectionDetails.selfServe;
            collectionMeta.memberExpiryDays =
                this.state.copyCollectionDetails.memberExpiryDays;
            collectionMeta.serviceExpiryDays =
                this.state.copyCollectionDetails.serviceExpiryDays;
        } else if (this.props.category === 'domain') {
            collectionMeta.memberExpiryDays =
                this.state.copyCollectionDetails.memberExpiryDays;
            collectionMeta.serviceExpiryDays =
                this.state.copyCollectionDetails.serviceExpiryDays;
            collectionMeta.groupExpiryDays =
                this.state.copyCollectionDetails.groupExpiryDays;
            collectionMeta.tokenExpiryMins =
                this.state.copyCollectionDetails.tokenExpiryMins;
            collectionMeta.roleCertExpiryMins =
                this.state.copyCollectionDetails.roleCertExpiryMins;
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
                    enableSubmit: false,
                });
                setTimeout(
                    () =>
                        this.setState({
                            showSuccess: false,
                        }),
                    MODAL_TIME_OUT
                );
                this.reloadCollection();
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
                key={'setting-update-modal'}
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

        let submitButton = this.state.enableSubmit ? (
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
        (this.props.category === 'role' || this.props.category === 'group') &&
            rows.push(
                <StyledSettingRow
                    key={'setting-row-reviewEnabled'}
                    domain={domain}
                    name='reviewEnabled'
                    label='Review'
                    type='switch'
                    desc={reviewDesc}
                    value={this.state.copyCollectionDetails.reviewEnabled}
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
        (this.props.category === 'role' || this.props.category === 'group') &&
            rows.push(
                <StyledSettingRow
                    key={'setting-row-selfServe'}
                    domain={domain}
                    name='selfServe'
                    label='Self-Service'
                    type='switch'
                    desc={selfServiceDesc}
                    value={this.state.copyCollectionDetails.selfServe}
                    api={this.api}
                    onValueChange={this.onValueChange}
                    _csrf={this.props._csrf}
                    justificationRequired={this.props.justificationRequired}
                    userProfileLink={this.props.userProfileLink}
                />
            );

        rows.push(
            <StyledSettingRow
                key={'setting-row-memberExpiryDays'}
                domain={domain}
                name='memberExpiryDays'
                label='User Expiry'
                type='input'
                desc={
                    'All user members in the ' +
                    this.props.category +
                    ' will have specified max expiry days'
                }
                unit='Days'
                value={this.state.copyCollectionDetails.memberExpiryDays}
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
                    key={'setting-row-memberReviewDays'}
                    domain={domain}
                    name='memberReviewDays'
                    label='User Review'
                    type='input'
                    desc='All user members in the role will have specified review days'
                    unit='Days'
                    value={this.state.copyCollectionDetails.memberReviewDays}
                    api={this.api}
                    onValueChange={this.onValueChange}
                    _csrf={this.props._csrf}
                    justificationRequired={this.props.justificationRequired}
                    userProfileLink={this.props.userProfileLink}
                />
            );

        (this.props.category === 'role' || this.props.category === 'domain') &&
            rows.push(
                <StyledSettingRow
                    key={'setting-row-groupExpiryDays'}
                    domain={domain}
                    name='groupExpiryDays'
                    label='Group Expiry'
                    type='input'
                    desc={
                        'All group members in the ' +
                        this.props.category +
                        ' will have specified max expiry days'
                    }
                    unit='Days'
                    value={this.state.copyCollectionDetails.groupExpiryDays}
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
                    key={'setting-row-groupReviewDays'}
                    domain={domain}
                    name='groupReviewDays'
                    label='Group Review'
                    type='input'
                    desc='All groups in the role will have specified max review days'
                    unit='Days'
                    value={this.state.copyCollectionDetails.groupReviewDays}
                    api={this.api}
                    onValueChange={this.onValueChange}
                    _csrf={this.props._csrf}
                    justificationRequired={this.props.justificationRequired}
                    userProfileLink={this.props.userProfileLink}
                />
            );

        rows.push(
            <StyledSettingRow
                key={'setting-row-serviceExpiryDays'}
                domain={domain}
                name='serviceExpiryDays'
                label='Service Expiry'
                type='input'
                unit='Days'
                desc={
                    'All services in the ' +
                    this.props.category +
                    ' will have specified max expiry days'
                }
                value={this.state.copyCollectionDetails.serviceExpiryDays}
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
                    key={'setting-row-serviceReviewDays'}
                    domain={domain}
                    name='serviceReviewDays'
                    label='Service Review'
                    type='input'
                    desc='All service members in the role will have specified review days'
                    unit='Days'
                    value={this.state.copyCollectionDetails.serviceReviewDays}
                    api={this.api}
                    onValueChange={this.onValueChange}
                    _csrf={this.props._csrf}
                    justificationRequired={this.props.justificationRequired}
                    userProfileLink={this.props.userProfileLink}
                />
            );

        (this.props.category === 'role' || this.props.category === 'domain') &&
            rows.push(
                <StyledSettingRow
                    key={'setting-row-tokenExpiryMins'}
                    domain={domain}
                    name='tokenExpiryMins'
                    label='Token Expiry'
                    type='input'
                    unit='Mins'
                    desc={
                        'Tokens issued for this ' +
                        this.props.category +
                        ' will have specified max timeout in mins'
                    }
                    value={this.state.copyCollectionDetails.tokenExpiryMins}
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
                    key={'setting-row-certExpiryMins'}
                    domain={domain}
                    name='certExpiryMins'
                    label='Certificate Expiry'
                    type='input'
                    unit='Mins'
                    desc='Certs issued for this role will have specified max timeout in mins'
                    value={this.state.copyCollectionDetails.certExpiryMins}
                    api={this.api}
                    onValueChange={this.onValueChange}
                    _csrf={this.props._csrf}
                    justificationRequired={this.props.justificationRequired}
                    userProfileLink={this.props.userProfileLink}
                />
            );

        this.props.category === 'domain' &&
            rows.push(
                <StyledSettingRow
                    key={'setting-row-roleCertExpiryMins'}
                    domain={domain}
                    name='roleCertExpiryMins'
                    label='Role Certificate Expiry'
                    type='input'
                    unit='Mins'
                    desc={
                        'Role Certs issued for this domain will have specified max timeout in mins'
                    }
                    value={this.state.copyCollectionDetails.roleCertExpiryMins}
                    api={this.api}
                    onValueChange={this.onValueChange}
                    _csrf={this.props._csrf}
                    justificationRequired={this.props.justificationRequired}
                    userProfileLink={this.props.userProfileLink}
                />
            );

        (this.props.category === 'role' || this.props.category === 'group') &&
            rows.push(
                <StyledSettingRow
                    key={'setting-row-userAuthorityFilter'}
                    domain={domain}
                    name='userAuthorityFilter'
                    label='User Authority Filter'
                    type='dropdown'
                    options={this.state.boolUserAuthorityAttributes}
                    placeholder='User Authority Filter'
                    desc='membership filtered based on user authority configured attributes'
                    value={this.state.copyCollectionDetails.userAuthorityFilter}
                    api={this.api}
                    onValueChange={this.onValueChange}
                    _csrf={this.props._csrf}
                    justificationRequired={this.props.justificationRequired}
                    userProfileLink={this.props.userProfileLink}
                />
            );

        (this.props.category === 'role' || this.props.category === 'group') &&
            rows.push(
                <StyledSettingRow
                    key={'setting-row-userAuthorityExpiration'}
                    domain={domain}
                    name='userAuthorityExpiration'
                    label='User Authority Expiration'
                    type='dropdown'
                    options={this.state.dateUserAuthorityAttributes}
                    placeholder='User Authority Expiration'
                    desc='expiration enforced by a user authority configured attribute'
                    value={
                        this.state.copyCollectionDetails.userAuthorityExpiration
                    }
                    api={this.api}
                    onValueChange={this.onValueChange}
                    _csrf={this.props._csrf}
                    justificationRequired={this.props.justificationRequired}
                    userProfileLink={this.props.userProfileLink}
                />
            );

        rows.push();

        return (
            <RolesSectionDiv>
                <StyleTable data-testid='setting-table'>
                    <tbody>{rows}</tbody>
                </StyleTable>
                <AddContainerDiv key={'setting-table-button'}>
                    <div>
                        {submitButton}
                        {submitSettings}
                        <Button secondary onClick={this.toggleReset}>
                            Reset
                        </Button>
                        {message}
                    </div>
                </AddContainerDiv>
            </RolesSectionDiv>
        );
    }
}
