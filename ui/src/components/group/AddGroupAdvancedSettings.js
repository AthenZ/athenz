import React from 'react';
import SettingRow from '../settings/SettingRow';
import {
    AUDIT_DESC,
    AUDIT_ENABLED_TOOLTIP,
    AUTHORITY_FILTER_DESC,
    DELETE_PROTECTION_DESC,
    MAX_MEMBERS_DESC,
    MEMBER_EXPIRY_DAYS_DESC,
    REVIEW_DESC,
    REVIEW_ENABLED_TOOLTIP,
    SELF_RENEW_DESC,
    SELF_SERVICE_DESC,
    SERVICE_EXPIRY_DAYS_DESC,
    GROUP_ROLE_DOMAIN_FILTER_DESC,
    AUTHORITY_EXPIRY,
    AUTHORITY_EXPIRY_DESC,
    AUTHORITY_FILTERS,
    SELF_RENEW_MINS_DESC,
    GROUP,
} from '../constants/constants';

export default class AddGroupAdvancedSettings extends React.Component {
    constructor(props) {
        super(props);

        this.advancedSettingsChanged = this.props.advancedSettingsChanged;
        this.reviewEnabledChanged = this.props.reviewEnabledChanged;
        this.auditEnabledChanged = this.props.auditEnabledChanged;
        this.deleteProtectionChanged = this.props.deleteProtectionChanged;

        let boolUserAuthorityAttributes = [];
        let dateUserAuthorityAttributes = [];

        if (this.props.userAuthorityAttributes?.attributes) {
            let authorityAttributes =
                this.props.userAuthorityAttributes.attributes;

            if (authorityAttributes.bool?.values) {
                for (const attribute of authorityAttributes.bool.values) {
                    boolUserAuthorityAttributes.push({
                        value: attribute,
                        name: attribute,
                    });
                }
            }

            if (authorityAttributes.date?.values) {
                for (const attribute of authorityAttributes.date.values) {
                    dateUserAuthorityAttributes.push({
                        value: attribute,
                        name: attribute,
                    });
                }
            }
        }

        this.state = {
            boolUserAuthorityAttributes,
            dateUserAuthorityAttributes,
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
                    this.props.members.length
                }
                desc={AUDIT_DESC(GROUP)}
                onValueChange={this.auditEnabledChanged}
                value={this.props.group.auditEnabled}
                inModal={true}
                tooltip={AUDIT_ENABLED_TOOLTIP(GROUP)}
            />,
            <SettingRow
                key={'setting-row-reviewEnabled'}
                name='reviewEnabled'
                label='Review'
                type='switch'
                desc={REVIEW_DESC(GROUP)}
                onValueChange={this.reviewEnabledChanged}
                value={this.props.reviewEnabled}
                inModal={true}
                tooltip={REVIEW_ENABLED_TOOLTIP(GROUP)}
            />,
            <SettingRow
                key={'setting-row-deleteProtection'}
                name='deleteProtection'
                label='Delete Protection'
                type='switch'
                desc={DELETE_PROTECTION_DESC(GROUP)}
                onValueChange={this.deleteProtectionChanged}
                value={this.props.group['deleteProtection']}
                inModal={true}
            />,
            <SettingRow
                key={'setting-row-selfServe'}
                name='selfServe'
                label='Self-Service'
                type='switch'
                desc={SELF_SERVICE_DESC(GROUP)}
                onValueChange={this.advancedSettingsChanged}
                value={this.props.group['selfServe']}
                inModal={true}
            />,
            <SettingRow
                key={'setting-row-selfRenew'}
                name='selfRenew'
                label='Self-Renew'
                type='switch'
                desc={SELF_RENEW_DESC(GROUP)}
                onValueChange={this.advancedSettingsChanged}
                value={this.props.group['selfRenew']}
                inModal={true}
            />,
            <SettingRow
                key={'setting-row-selfRenewMins'}
                name='selfRenewMins'
                label='Self Renew'
                type='input'
                desc={SELF_RENEW_MINS_DESC}
                unit='Mins'
                disabled={!this.props.group['selfRenew']}
                onValueChange={this.advancedSettingsChanged}
                inModal={true}
            />,
            <SettingRow
                key={'setting-row-memberExpiryDays'}
                name='memberExpiryDays'
                label='User Expiry'
                type='input'
                desc={MEMBER_EXPIRY_DAYS_DESC(GROUP)}
                unit='Days'
                onValueChange={this.advancedSettingsChanged}
                inModal={true}
            />,
            <SettingRow
                key={'setting-row-serviceExpiryDays'}
                name='serviceExpiryDays'
                label='Service Expiry'
                type='input'
                unit='Days'
                desc={SERVICE_EXPIRY_DAYS_DESC(GROUP)}
                onValueChange={this.advancedSettingsChanged}
                inModal={true}
            />,
            <SettingRow
                key={'setting-row-userAuthorityFilter'}
                name='userAuthorityFilter'
                label={AUTHORITY_FILTERS}
                type='multiselect'
                options={this.state.boolUserAuthorityAttributes}
                placeholder={AUTHORITY_FILTERS}
                desc={AUTHORITY_FILTER_DESC}
                onValueChange={this.advancedSettingsChanged}
                value={''}
                inModal={true}
            />,
            <SettingRow
                key={'setting-row-userAuthorityExpiration'}
                name='userAuthorityExpiration'
                label='User Authority Expiration'
                type='dropdown'
                options={this.state.dateUserAuthorityAttributes}
                placeholder={AUTHORITY_EXPIRY}
                desc={AUTHORITY_EXPIRY_DESC}
                onValueChange={this.advancedSettingsChanged}
                inModal={true}
            />,
            <SettingRow
                key={'setting-row-maxmembers'}
                name='maxMembers'
                label='Max Members'
                type='input'
                unit='Number'
                desc={MAX_MEMBERS_DESC(GROUP)}
                onValueChange={this.advancedSettingsChanged}
                inModal={true}
            />,
            <SettingRow
                key={'setting-row-domainfilter'}
                name='principalDomainFilter'
                label='Domain Filter'
                type='text'
                desc={GROUP_ROLE_DOMAIN_FILTER_DESC}
                onValueChange={this.advancedSettingsChanged}
                inModal={true}
            />,
        ];
    }
}
