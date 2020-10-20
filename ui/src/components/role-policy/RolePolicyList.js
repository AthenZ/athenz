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
import Button from '../denali/Button';
import AddPolicyToRole from '../policy/AddPolicyToRole';
import RolePolicyRow from './RolePolicyRow';
import Alert from '../denali/Alert';
import DeleteModal from '../modal/DeleteModal';
import NameUtils from '../utils/NameUtils';
import { MODAL_TIME_OUT } from '../constants/constants';
import RequestUtils from '../utils/RequestUtils';

const PolicySectionDiv = styled.div`
    margin: 20px;
`;

const AddContainerDiv = styled.div`
    padding-bottom: 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-flow: row nowrap;
    float: right;
`;

const PolicyTable = styled.table`
    width: 100%;
    border-spacing: 0 15px;
    display: table;
    border-collapse: separate;
    border-color: grey;
`;

export default class RolePolicyList extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.onSubmitDeletePolicy = this.onSubmitDeletePolicy.bind(this);
        this.onCancelDeletePolicy = this.onCancelDeletePolicy.bind(this);
        this.toggleAddPolicy = this.toggleAddPolicy.bind(this);
        this.reloadPolicies = this.reloadPolicies.bind(this);
        this.closeModal = this.closeModal.bind(this);
        this.state = {
            list: props.policies || [],
            showAddPolicy: false,
        };
    }

    onSubmitDeletePolicy() {
        this.api
            .deletePolicy(
                this.props.domain,
                this.state.deletePolicyName,
                this.props._csrf
            )
            .then(() => {
                this.reloadPolicies(
                    `Successfully deleted policy ${this.state.deletePolicyName}`
                );
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    onCancelDeletePolicy() {
        this.setState({
            showDelete: false,
            deletePolicyName: null,
        });
    }

    onClickDeletePolicy(policyName) {
        this.setState({
            showDelete: true,
            deletePolicyName: policyName,
            errorMessage: null,
        });
    }

    reloadPolicies(successMessage) {
        let role = this.props.role;

        this.api
            .getPolicies(this.props.domain, true)
            .then((data) => {
                let filteredPolicies = data;
                if (role) {
                    filteredPolicies = data.filter((policy) => {
                        let included = false;
                        policy.assertions.forEach((element) => {
                            if (
                                NameUtils.getShortName(
                                    ':role.',
                                    element.role
                                ) == role
                            ) {
                                included = true;
                            }
                        });
                        return included;
                    });
                }

                this.setState({
                    list: filteredPolicies,
                    showAddPolicy: false,
                    showSuccess: true,
                    successMessage,
                    showDelete: false,
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

    toggleAddPolicy() {
        this.setState({
            showAddPolicy: !this.state.showAddPolicy,
        });
    }

    closeModal() {
        this.setState({ showSuccess: null });
    }

    render() {
        const { domain, role } = this.props;
        const rows = this.state.list.map((item, i) => {
            let name = NameUtils.getShortName(':policy.', item.name);
            let onClickDeletePolicy = this.onClickDeletePolicy.bind(this, name);
            return (
                <RolePolicyRow
                    name={name}
                    domain={domain}
                    role={role}
                    modified={item.modified}
                    api={this.api}
                    key={item.name}
                    _csrf={this.props._csrf}
                    onClickDeletePolicy={onClickDeletePolicy}
                />
            );
        });
        let addPolicy = this.state.showAddPolicy ? (
            <AddPolicyToRole
                showAddPolicy={this.state.showAddPolicy}
                onCancel={this.toggleAddPolicy}
                onSubmit={this.reloadPolicies}
                domain={domain}
                role={role}
                api={this.api}
                _csrf={this.props._csrf}
            />
        ) : (
            ''
        );

        return (
            <PolicySectionDiv data-testid='policylist'>
                <AddContainerDiv>
                    <div>
                        <Button secondary onClick={this.toggleAddPolicy}>
                            Add Policy
                        </Button>
                        {addPolicy}
                    </div>
                </AddContainerDiv>
                <PolicyTable>
                    <tbody>{rows}</tbody>
                </PolicyTable>
                {this.state.showSuccess ? (
                    <Alert
                        isOpen={this.state.showSuccess}
                        title={this.state.successMessage}
                        onClose={this.closeModal}
                        type='success'
                    />
                ) : null}
                {this.state.showDelete ? (
                    <DeleteModal
                        name={this.state.deletePolicyName}
                        isOpen={this.state.showDelete}
                        cancel={this.onCancelDeletePolicy}
                        submit={this.onSubmitDeletePolicy}
                        errorMessage={this.state.errorMessage}
                        message={
                            'Are you sure you want to permanently delete the Policy '
                        }
                    />
                ) : null}
            </PolicySectionDiv>
        );
    }
}
