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
import SettingTable from './SettingTable';
import RequestUtils from '../utils/RequestUtils';

const RolesSectionDiv = styled.div`
    margin: 20px;
`;

export default class SettingList extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.onSubmit = this.onSubmit.bind(this);
        this.reloadRole = this.reloadRole.bind(this);
        this.state = {
            roleDetails: props.roleDetails,
            errorMessage: null,
        };
    }

    componentDidUpdate = (prevProps) => {
        if (
            prevProps.role !== this.props.role ||
            prevProps.domain !== this.props.domain
        ) {
            this.setState({
                roleDetails: this.props.roleDetails,
            });
        }
    };

    onSubmit() {
        this.reloadRole();
    }

    reloadRole() {
        this.api
            .getRole(this.props.domain, this.props.role, false, false, false)
            .then((role) => {
                this.setState({
                    roleDetails: role,
                    errorMessage: null,
                });
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    render() {
        const { domain, role } = this.props;

        return (
            <RolesSectionDiv data-testid='setting-list'>
                <SettingTable
                    domain={domain}
                    role={role}
                    roleDetails={this.state.roleDetails}
                    onSubmit={this.onSubmit}
                    api={this.api}
                    _csrf={this.props._csrf}
                    justificationRequired={this.props.isDomainAuditEnabled}
                    userProfileLink={this.props.userProfileLink}
                />
            </RolesSectionDiv>
        );
    }
}
