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
import styled from '@emotion/styled';
import SettingRow from './SettingRow';
import Button from '../denali/Button';
import UpdateModal from '../modal/UpdateModal';
import Alert from '../denali/Alert';
import RequestUtils from '../utils/RequestUtils';
import _ from 'lodash';
import {
    ADD_GROUP_DELETE_PROTECTION_DESC,
    ADD_ROLE_DELETE_PROTECTION_DESC,
    MODAL_TIME_OUT,
    SELF_RENEW_MINS_DESC,
} from '../constants/constants';
import { updateSettings } from '../../redux/thunks/collections';
import { connect } from 'react-redux';
import { selectIsLoading } from '../../redux/selectors/loading';
import { selectAuthorityAttributes } from '../../redux/selectors/domains';
import { ReduxPageLoader } from '../denali/ReduxPageLoader';
import { selectDomainAuditEnabled } from '../../redux/selectors/domainData';

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

class SettingTable extends React.Component {
    constructor(props) {
        super(props);
        this.toggleSubmit = this.toggleSubmit.bind(this);
        this.toggleReset = this.toggleReset.bind(this);
        this.onSubmitUpdate = this.onSubmitUpdate.bind(this);
        this.onClickUpdateCancel = this.onClickUpdateCancel.bind(this);
        this.closeModal = this.closeModal.bind(this);
        this.updateCollectionMeta = this.updateCollectionMeta.bind(this);
        this.onValueChange = this.onValueChange.bind(this);
        this.setCollectionDetails = this.setCollectionDetails.bind(this);
        this.saveJustification = this.saveJustification.bind(this);
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
            justification: '',
        };
    }

    saveJustification(val) {
        this.setState({ justification: val });
    }

    setCollectionDetails(collection) {
        let collectionDetails = {
            description: collection.description,
            reviewEnabled: !!collection.reviewEnabled,
            auditEnabled: !!collection.auditEnabled,
            hasRoleMembers:
                this.props.category === 'role' &&
                collection.roleMembers &&
                Object.keys(collection.roleMembers).length !== 0,
            hasGroupMembers:
                this.props.category === 'group' &&
                collection.groupMembers &&
                Object.keys(collection.groupMembers).length !== 0,
            deleteProtection: !!collection.deleteProtection,
            selfServe: !!collection.selfServe,
            selfRenew: !!collection.selfRenew,
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
            maxMembers:
                collection.maxMembers === undefined
                    ? ''
                    : collection.maxMembers.toString(),
            selfRenewMins:
                collection.selfRenewMins === undefined
                    ? ''
                    : collection.selfRenewMins.toString(),
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
            this.props.isDomainAuditEnabled &&
            (this.state.justification === undefined ||
                this.state.justification.trim() === '')
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
            justification: '',
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

    updateCollectionMeta() {
        let collectionMeta = {};

        if (this.props.category === 'role') {
            collectionMeta = this.state.copyCollectionDetails;
        } else if (this.props.category === 'group') {
            collectionMeta.auditEnabled =
                this.state.copyCollectionDetails.auditEnabled;
            collectionMeta.reviewEnabled =
                this.state.copyCollectionDetails.reviewEnabled;
            collectionMeta.selfServe =
                this.state.copyCollectionDetails.selfServe;
            collectionMeta.selfRenew =
                this.state.copyCollectionDetails.selfRenew;
            collectionMeta.selfRenewMins =
                this.state.copyCollectionDetails.selfRenewMins;
            collectionMeta.memberExpiryDays =
                this.state.copyCollectionDetails.memberExpiryDays;
            collectionMeta.serviceExpiryDays =
                this.state.copyCollectionDetails.serviceExpiryDays;
            collectionMeta.userAuthorityFilter =
                this.state.copyCollectionDetails.userAuthorityFilter;
            collectionMeta.userAuthorityExpiration =
                this.state.copyCollectionDetails.userAuthorityExpiration;
            collectionMeta.deleteProtection =
                this.state.copyCollectionDetails.deleteProtection;
            collectionMeta.maxMembers =
                this.state.copyCollectionDetails.maxMembers;
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

        this.props
            .updateSettings(
                this.props.domain,
                collectionMeta,
                this.props.collection,
                this.props._csrf,
                this.props.category
            )
            .then(() => {
                const { collectionDetails } = this.props;
                let newCollectionDetails = this.setCollectionDetails({
                    ...collectionDetails,
                });
                this.setState({
                    originalCollectionDetails: newCollectionDetails,
                    copyCollectionDetails: _.cloneDeep(newCollectionDetails),
                    errorMessage: null,
                    showSuccess: true,
                    showSubmit: false,
                    enableSubmit: false,
                    justification: '',
                });
                setTimeout(
                    () =>
                        this.setState({
                            showSuccess: false,
                        }),
                    MODAL_TIME_OUT
                );
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    render() {
        let rows = [];

        let submitSettings = this.state.showSubmit ? (
            <UpdateModal
                name={this.props.collection}
                isOpen={this.state.showSubmit}
                cancel={this.onClickUpdateCancel}
                submit={this.onSubmitUpdate}
                key={'setting-update-modal'}
                message={
                    'Are you sure you want to permanently change the setting for ' +
                    this.props.category +
                    ' '
                }
                showJustification={this.props.isDomainAuditEnabled}
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
                    domain={this.props.domain}
                    name='reviewEnabled'
                    label='Review'
                    type='switch'
                    desc={reviewDesc}
                    value={this.state.copyCollectionDetails.reviewEnabled}
                    onValueChange={this.onValueChange}
                    _csrf={this.props._csrf}
                />
            );

        let auditEnabledDesc =
            'Flag indicates whether or not ' +
            this.props.category +
            ' updates require explicit auditing approval process';
        (this.props.category === 'role' || this.props.category === 'group') &&
            this.props.isDomainAuditEnabled &&
            rows.push(
                <StyledSettingRow
                    key={'setting-row-auditEnabled'}
                    disabled={
                        this.state.originalCollectionDetails.auditEnabled ||
                        this.state.copyCollectionDetails.hasRoleMembers ||
                        this.state.copyCollectionDetails.hasGroupMembers
                    }
                    domain={this.props.domain}
                    name='auditEnabled'
                    label='Audit Enabled'
                    type='switch'
                    desc={auditEnabledDesc}
                    value={this.state.copyCollectionDetails.auditEnabled}
                    onValueChange={this.onValueChange}
                    _csrf={this.props._csrf}
                />
            );

        (this.props.category === 'role' || this.props.category === 'group') &&
            rows.push(
                <StyledSettingRow
                    key={`setting-row-${this.props.category}-deleteProtection`}
                    domain={this.props.domain}
                    name='deleteProtection'
                    label='Delete Protection'
                    type='switch'
                    desc={
                        this.props.category === 'role'
                            ? ADD_ROLE_DELETE_PROTECTION_DESC
                            : ADD_GROUP_DELETE_PROTECTION_DESC
                    }
                    value={this.state.copyCollectionDetails.deleteProtection}
                    onValueChange={this.onValueChange}
                    _csrf={this.props._csrf}
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
                    domain={this.props.domain}
                    name='selfServe'
                    label='Self-Service'
                    type='switch'
                    desc={selfServiceDesc}
                    value={this.state.copyCollectionDetails.selfServe}
                    onValueChange={this.onValueChange}
                    _csrf={this.props._csrf}
                />
            );

        let selfRenewDesc =
            'Flag indicates whether or not ' +
            this.props.category +
            ' allows self renew';
        (this.props.category === 'role' || this.props.category === 'group') &&
            rows.push(
                <StyledSettingRow
                    key={'setting-row-selfRenew'}
                    domain={this.props.domain}
                    name='selfRenew'
                    label='Self-Renew'
                    type='switch'
                    desc={selfRenewDesc}
                    value={this.state.copyCollectionDetails.selfRenew}
                    onValueChange={this.onValueChange}
                    _csrf={this.props._csrf}
                />
            );

        (this.props.category === 'role' || this.props.category === 'group') &&
            rows.push(
                <StyledSettingRow
                    key={'setting-row-selfRenewMins'}
                    domain={this.props.domain}
                    name='selfRenewMins'
                    label='Self Renew'
                    type='input'
                    unit='Mins'
                    desc={SELF_RENEW_MINS_DESC}
                    value={this.state.copyCollectionDetails.selfRenewMins}
                    disabled={!this.state.copyCollectionDetails.selfRenew}
                    onValueChange={this.onValueChange}
                    _csrf={this.props._csrf}
                />
            );

        rows.push(
            <StyledSettingRow
                key={'setting-row-memberExpiryDays'}
                domain={this.props.domain}
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
                onValueChange={this.onValueChange}
                _csrf={this.props._csrf}
            />
        );

        this.props.category === 'role' &&
            rows.push(
                <StyledSettingRow
                    key={'setting-row-memberReviewDays'}
                    domain={this.props.domain}
                    name='memberReviewDays'
                    label='User Review'
                    type='input'
                    desc='All user members in the role will have specified review days'
                    unit='Days'
                    value={this.state.copyCollectionDetails.memberReviewDays}
                    onValueChange={this.onValueChange}
                    _csrf={this.props._csrf}
                />
            );

        (this.props.category === 'role' || this.props.category === 'domain') &&
            rows.push(
                <StyledSettingRow
                    key={'setting-row-groupExpiryDays'}
                    domain={this.props.domain}
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
                    onValueChange={this.onValueChange}
                    _csrf={this.props._csrf}
                />
            );

        this.props.category === 'role' &&
            rows.push(
                <StyledSettingRow
                    key={'setting-row-groupReviewDays'}
                    domain={this.props.domain}
                    name='groupReviewDays'
                    label='Group Review'
                    type='input'
                    desc='All groups in the role will have specified max review days'
                    unit='Days'
                    value={this.state.copyCollectionDetails.groupReviewDays}
                    onValueChange={this.onValueChange}
                    _csrf={this.props._csrf}
                />
            );

        rows.push(
            <StyledSettingRow
                key={'setting-row-serviceExpiryDays'}
                domain={this.props.domain}
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
                onValueChange={this.onValueChange}
                _csrf={this.props._csrf}
            />
        );

        this.props.category === 'role' &&
            rows.push(
                <StyledSettingRow
                    key={'setting-row-serviceReviewDays'}
                    domain={this.props.domain}
                    name='serviceReviewDays'
                    label='Service Review'
                    type='input'
                    desc='All service members in the role will have specified review days'
                    unit='Days'
                    value={this.state.copyCollectionDetails.serviceReviewDays}
                    onValueChange={this.onValueChange}
                    _csrf={this.props._csrf}
                />
            );

        (this.props.category === 'role' || this.props.category === 'domain') &&
            rows.push(
                <StyledSettingRow
                    key={'setting-row-tokenExpiryMins'}
                    domain={this.props.domain}
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
                    onValueChange={this.onValueChange}
                    _csrf={this.props._csrf}
                />
            );

        this.props.category === 'role' &&
            rows.push(
                <StyledSettingRow
                    key={'setting-row-certExpiryMins'}
                    domain={this.props.domain}
                    name='certExpiryMins'
                    label='Certificate Expiry'
                    type='input'
                    unit='Mins'
                    desc='Certs issued for this role will have specified max timeout in mins'
                    value={this.state.copyCollectionDetails.certExpiryMins}
                    onValueChange={this.onValueChange}
                    _csrf={this.props._csrf}
                />
            );

        this.props.category === 'domain' &&
            rows.push(
                <StyledSettingRow
                    key={'setting-row-roleCertExpiryMins'}
                    domain={this.props.domain}
                    name='roleCertExpiryMins'
                    label='Role Certificate Expiry'
                    type='input'
                    unit='Mins'
                    desc={
                        'Role Certs issued for this domain will have specified max timeout in mins'
                    }
                    value={this.state.copyCollectionDetails.roleCertExpiryMins}
                    onValueChange={this.onValueChange}
                    _csrf={this.props._csrf}
                />
            );

        (this.props.category === 'role' || this.props.category === 'group') &&
            rows.push(
                <StyledSettingRow
                    key={'setting-row-userAuthorityFilter'}
                    domain={this.props.domain}
                    name='userAuthorityFilter'
                    label='User Authority Filter'
                    type='dropdown'
                    options={this.state.boolUserAuthorityAttributes}
                    placeholder='User Authority Filter'
                    desc='membership filtered based on user authority configured attributes'
                    value={this.state.copyCollectionDetails.userAuthorityFilter}
                    onValueChange={this.onValueChange}
                    _csrf={this.props._csrf}
                />
            );

        (this.props.category === 'role' || this.props.category === 'group') &&
            rows.push(
                <StyledSettingRow
                    key={'setting-row-userAuthorityExpiration'}
                    domain={this.props.domain}
                    name='userAuthorityExpiration'
                    label='User Authority Expiration'
                    type='dropdown'
                    options={this.state.dateUserAuthorityAttributes}
                    placeholder='User Authority Expiration'
                    desc='expiration enforced by a user authority configured attribute'
                    value={
                        this.state.copyCollectionDetails.userAuthorityExpiration
                    }
                    onValueChange={this.onValueChange}
                    _csrf={this.props._csrf}
                />
            );

        this.props.category === 'role' &&
            rows.push(
                <StyledSettingRow
                    key={'setting-row-description'}
                    domain={this.props.domain}
                    name='description'
                    label='Role Description'
                    type='text'
                    placeholder='Role Description'
                    desc='Role Description (Optional)'
                    value={this.state.copyCollectionDetails.description}
                    onValueChange={this.onValueChange}
                    _csrf={this.props._csrf}
                />
            );

        (this.props.category === 'role' || this.props.category === 'group') &&
            rows.push(
                <StyledSettingRow
                    key={'setting-row-maxmembers'}
                    domain={this.props.domain}
                    name='maxMembers'
                    label='Max Members'
                    type='input'
                    unit='Number'
                    desc={
                        'Maximum number of members allowed in the ' +
                        this.props.category
                    }
                    value={this.state.copyCollectionDetails.maxMembers}
                    onValueChange={this.onValueChange}
                    _csrf={this.props._csrf}
                />
            );

        return this.props.isLoading.length !== 0 ? (
            <ReduxPageLoader message={'Loading setting'} />
        ) : (
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

const mapStateToProps = (state, props) => {
    return {
        ...props,
        userAuthorityAttributes: selectAuthorityAttributes(state),
        isLoading: selectIsLoading(state),
        isDomainAuditEnabled: selectDomainAuditEnabled(state),
    };
};

const mapDispatchToProps = (dispatch) => ({
    updateSettings: (
        domainName,
        collectionMeta,
        collectionName,
        _csrf,
        category
    ) =>
        dispatch(
            updateSettings(
                domainName,
                collectionMeta,
                collectionName,
                _csrf,
                category
            )
        ),
});

export default connect(mapStateToProps, mapDispatchToProps)(SettingTable);
