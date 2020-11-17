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
import ReviewTable from './ReviewTable';
import Alert from '../denali/Alert';

const RolesSectionDiv = styled.div`
    margin: 20px;
`;

export default class ReviewList extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.state = {
            showuser: false,
            members: props.members || [],
            errorMessage: null,
        };
        this.closeModal = this.closeModal.bind(this);
        this.submitSuccess = this.submitSuccess.bind(this);
    }

    componentDidUpdate = (prevProps) => {
        if (
            prevProps.role !== this.props.role ||
            prevProps.domain !== this.props.domain
        ) {
            this.setState({
                members: this.props.members,
                showuser: false,
            });
        }
    };

    submitSuccess(successMessage) {
        this.setState({
            showSuccess: true,
            successMessage,
            errorMessage: null,
        });
    }

    closeModal() {
        this.setState({ showSuccess: null });
    }

    render() {
        const { domain, role, roleDetails } = this.props;

        return (
            <RolesSectionDiv data-testid='member-list'>
                <ReviewTable
                    domain={domain}
                    role={role}
                    roleDetails={roleDetails}
                    members={this.state.members}
                    api={this.api}
                    _csrf={this.props._csrf}
                    onUpdateSuccess={this.submitSuccess}
                    justificationRequired={this.props.isDomainAuditEnabled}
                    userProfileLink={this.props.userProfileLink}
                />
                {this.state.showSuccess ? (
                    <Alert
                        isOpen={this.state.showSuccess}
                        title={this.state.successMessage}
                        onClose={this.closeModal}
                        type='success'
                    />
                ) : null}
            </RolesSectionDiv>
        );
    }
}
