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
import { colors } from '../denali/styles';
import ReviewTable from './ReviewTable';
import Alert from '../denali/Alert';
import { MODAL_TIME_OUT } from '../constants/constants';
import RequestUtils from '../utils/RequestUtils';

const RolesSectionDiv = styled.div`
    margin: 20px;
`;

const RoleLabel = styled.label`
    color: ${colors.grey800};
    margin-left: 5px;
    white-space: nowrap;
    font: 300 14px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
`;

const SliderDiv = styled.div`
    vertical-align: middle;
`;

const AddContainerDiv = styled.div`
    padding-bottom: 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-flow: row nowrap;
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
        this.reloadMembers = this.reloadMembers.bind(this);
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

    reloadMembers(successMessage) {
        this.api
            .getRole(this.props.domain, this.props.role, true, true, true)
            .then((role) => {
                this.setState({
                    members: role.members,
                    showSuccess: true,
                    successMessage,
                    errorMessage: null,
                });
                // this is to close the success alert
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

    closeModal() {
        this.setState({ showSuccess: null });
    }

    render() {
        const { domain, role } = this.props;

        return (
            <RolesSectionDiv data-testid='member-list'>
                <ReviewTable
                    domain={domain}
                    role={role}
                    members={this.state.members}
                    api={this.api}
                    _csrf={this.props._csrf}
                    onUpdateSuccess={this.reloadMembers}
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
