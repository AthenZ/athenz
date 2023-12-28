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
import {
    ADD_ROLE_REVIEW_ENABLED_TOOLTIP,
    ADD_ROLE_REVIEW_DESC,
    ADD_ROLE_SELF_SERVICE_DESC,
    ADD_ROLE_MEMBER_EXPIRY_DAYS_DESC,
    ADD_ROLE_MEMBER_REVIEW_DAYS_DESC,
    ADD_ROLE_GROUP_EXPIRY_DAYS_DESC,
    ADD_ROLE_GROUP_REVIEW_DAYS_DESC,
    ADD_ROLE_SERVICE_EXPIRY_DAYS_DESC,
    ADD_ROLE_SERVICE_REVIEW_DAYS_DESC,
    ADD_ROLE_TOKEN_MAX_TIMEOUT_MINS_DESC,
    ADD_ROLE_CERT_MAX_TIMEOUT_MINS_DESC,
    ADD_ROLE_AUTHORITY_FILTER_DESC,
    ADD_ROLE_AUTHORITY_EXPIRY_DESC,
    ADD_ROLE_AUTHORITY_FILTER_PLACEHOLDER,
    ADD_ROLE_AUTHORITY_EXPIRY_PLACEHOLDER,
    ADD_ROLE_AUDIT_DESC,
    ADD_ROLE_AUDIT_ENABLED_TOOLTIP,
    ADD_ROLE_DELETE_PROTECTION_DESC,
    ADD_ROLE_DESCRIPTION,
    ADD_ROLE_SELF_RENEW_DESC,
    SELF_RENEW_MINS_DESC,
    ADD_ROLE_MAX_MEMBERS_DESC,
} from '../constants/constants';
import SettingRow from '../settings/SettingRow';

export default class AddRoleAdvancedSettings extends React.Component {
    constructor(props) {
        super(props);

        this.advancedSettingsChanged = this.props.advancedSettingsChanged;
        this.reviewEnabledChanged = this.props.reviewEnabledChanged;
        this.auditEnabledChanged = this.props.auditEnabledChanged;
        this.deleteProtectionChanged = this.props.deleteProtectionChanged;

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
            boolUserAuthorityAttributes: boolUserAuthorityAttributes,
            dateUserAuthorityAttributes: dateUserAuthorityAttributes,
        };
    }

    render() {
        return [
            <SettingRow
                key={'setting-row-auditEnabled'}
                name='auditEnabled'
                label='Audit'
                type='switch'
                disabled={
                    !this.props.isDomainAuditEnabled ||
                    this.props.members.length > 0
                }
                desc={ADD_ROLE_AUDIT_DESC}
                onValueChange={this.auditEnabledChanged}
                value={this.props.role.auditEnabled}
                userProfileLink={this.props.userProfileLink}
                inModal={true}
                tooltip={ADD_ROLE_AUDIT_ENABLED_TOOLTIP}
            />,
            <SettingRow
                key={'setting-row-reviewEnabled'}
                name='reviewEnabled'
                label='Review'
                type='switch'
                desc={ADD_ROLE_REVIEW_DESC}
                onValueChange={this.reviewEnabledChanged}
                value={this.props.reviewEnabled}
                userProfileLink={this.props.userProfileLink}
                inModal={true}
                tooltip={ADD_ROLE_REVIEW_ENABLED_TOOLTIP}
            />,
            <SettingRow
                key={'setting-row-deleteProtection'}
                name='deleteProtection'
                label='Delete Protection'
                type='switch'
                desc={ADD_ROLE_DELETE_PROTECTION_DESC}
                onValueChange={this.deleteProtectionChanged}
                value={this.props.role['deleteProtection']}
                userProfileLink={this.props.userProfileLink}
                inModal={true}
            />,
            <SettingRow
                key={'setting-row-selfServe'}
                name='selfServe'
                label='Self-Service'
                type='switch'
                desc={ADD_ROLE_SELF_SERVICE_DESC}
                onValueChange={this.advancedSettingsChanged}
                value={this.props.role['selfServe']}
                userProfileLink={this.props.userProfileLink}
                inModal={true}
            />,
            <SettingRow
                key={'setting-row-selfRenew'}
                name='selfRenew'
                label='Self-Renew'
                type='switch'
                desc={ADD_ROLE_SELF_RENEW_DESC}
                onValueChange={this.advancedSettingsChanged}
                value={this.props.role['selfRenew']}
                userProfileLink={this.props.userProfileLink}
                inModal={true}
            />,
            <SettingRow
                key={'setting-row-selfRenewMins'}
                name='selfRenewMins'
                label='Self Renew'
                type='input'
                desc={SELF_RENEW_MINS_DESC}
                unit='Mins'
                disabled={!this.props.role['selfRenew']}
                onValueChange={this.advancedSettingsChanged}
                userProfileLink={this.props.userProfileLink}
                inModal={true}
            />,
            <SettingRow
                key={'setting-row-memberExpiryDays'}
                name='memberExpiryDays'
                label='User Expiry'
                type='input'
                desc={ADD_ROLE_MEMBER_EXPIRY_DAYS_DESC}
                unit='Days'
                onValueChange={this.advancedSettingsChanged}
                userProfileLink={this.props.userProfileLink}
                inModal={true}
            />,
            <SettingRow
                key={'setting-row-memberReviewDays'}
                name='memberReviewDays'
                label='User Review'
                type='input'
                desc={ADD_ROLE_MEMBER_REVIEW_DAYS_DESC}
                unit='Days'
                onValueChange={this.advancedSettingsChanged}
                userProfileLink={this.props.userProfileLink}
                inModal={true}
            />,
            <SettingRow
                key={'setting-row-groupExpiryDays'}
                name='groupExpiryDays'
                label='Group Expiry'
                type='input'
                desc={ADD_ROLE_GROUP_EXPIRY_DAYS_DESC}
                unit='Days'
                onValueChange={this.advancedSettingsChanged}
                userProfileLink={this.props.userProfileLink}
                inModal={true}
            />,
            <SettingRow
                key={'setting-row-groupReviewDays'}
                name='groupReviewDays'
                label='Group Review'
                type='input'
                desc={ADD_ROLE_GROUP_REVIEW_DAYS_DESC}
                unit='Days'
                onValueChange={this.advancedSettingsChanged}
                userProfileLink={this.props.userProfileLink}
                inModal={true}
            />,
            <SettingRow
                key={'setting-row-serviceExpiryDays'}
                name='serviceExpiryDays'
                label='Service Expiry'
                type='input'
                unit='Days'
                desc={ADD_ROLE_SERVICE_EXPIRY_DAYS_DESC}
                onValueChange={this.advancedSettingsChanged}
                userProfileLink={this.props.userProfileLink}
                inModal={true}
            />,
            <SettingRow
                key={'setting-row-serviceReviewDays'}
                name='serviceReviewDays'
                label='Service Review'
                type='input'
                desc={ADD_ROLE_SERVICE_REVIEW_DAYS_DESC}
                unit='Days'
                onValueChange={this.advancedSettingsChanged}
                userProfileLink={this.props.userProfileLink}
                inModal={true}
            />,
            <SettingRow
                key={'setting-row-tokenExpiryMins'}
                name='tokenExpiryMins'
                label='Token Expiry'
                type='input'
                unit='Mins'
                desc={ADD_ROLE_TOKEN_MAX_TIMEOUT_MINS_DESC}
                onValueChange={this.advancedSettingsChanged}
                userProfileLink={this.props.userProfileLink}
                inModal={true}
            />,
            <SettingRow
                key={'setting-row-certExpiryMins'}
                name='certExpiryMins'
                label='Certificate Expiry'
                type='input'
                unit='Mins'
                desc={ADD_ROLE_CERT_MAX_TIMEOUT_MINS_DESC}
                onValueChange={this.advancedSettingsChanged}
                userProfileLink={this.props.userProfileLink}
                inModal={true}
            />,
            <SettingRow
                key={'setting-row-userAuthorityFilter'}
                name='userAuthorityFilter'
                label='User Authority Filter'
                type='dropdown'
                options={this.state.boolUserAuthorityAttributes}
                placeholder={ADD_ROLE_AUTHORITY_FILTER_PLACEHOLDER}
                desc={ADD_ROLE_AUTHORITY_FILTER_DESC}
                onValueChange={this.advancedSettingsChanged}
                userProfileLink={this.props.userProfileLink}
                inModal={true}
            />,
            <SettingRow
                key={'setting-row-userAuthorityExpiration'}
                name='userAuthorityExpiration'
                label='User Authority Expiration'
                type='dropdown'
                options={this.state.dateUserAuthorityAttributes}
                placeholder={ADD_ROLE_AUTHORITY_EXPIRY_PLACEHOLDER}
                desc={ADD_ROLE_AUTHORITY_EXPIRY_DESC}
                onValueChange={this.advancedSettingsChanged}
                userProfileLink={this.props.userProfileLink}
                inModal={true}
            />,
            <SettingRow
                key={'setting-row-description'}
                name='description'
                label='Description'
                type='text'
                desc={ADD_ROLE_DESCRIPTION}
                onValueChange={this.advancedSettingsChanged}
                userProfileLink={this.props.userProfileLink}
                inModal={true}
            />,
            <SettingRow
                key={'setting-row-maxmembers'}
                name='maxMembers'
                label='Max Members'
                type='input'
                unit='Number'
                desc={ADD_ROLE_MAX_MEMBERS_DESC}
                onValueChange={this.advancedSettingsChanged}
                userProfileLink={this.props.userProfileLink}
                inModal={true}
            />,
        ];
    }
}
