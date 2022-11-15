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
import Button from '../denali/Button';
import AddPolicyToRole from '../policy/AddPolicyToRole';
import Alert from '../denali/Alert';
import DeleteModal from '../modal/DeleteModal';
import NameUtils from '../utils/NameUtils';
import { MODAL_TIME_OUT } from '../constants/constants';
import RequestUtils from '../utils/RequestUtils';
import { selectActivePoliciesOnly } from '../../redux/selectors/policies';
import { deletePolicy } from '../../redux/thunks/policies';
import { connect } from 'react-redux';
import RolePolicyRow from './RolePolicyRow';
import { selectIsLoading } from '../../redux/selectors/loading';
import { ReduxPageLoader } from '../denali/ReduxPageLoader';

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

class RolePolicyList extends React.Component {
    constructor(props) {
        super(props);
        this.onSubmitDeletePolicy = this.onSubmitDeletePolicy.bind(this);
        this.onCancelDeletePolicy = this.onCancelDeletePolicy.bind(this);
        this.toggleAddPolicy = this.toggleAddPolicy.bind(this);
        this.reloadPolicies = this.reloadPolicies.bind(this);
        this.closeModal = this.closeModal.bind(this);
        this.state = {
            list: props.policies ? this.filterPolicies() : [],
            showAddPolicy: false,
        };
    }

    onSubmitDeletePolicy() {
        this.props
            .deletePolicy(
                this.props.domain,
                this.state.deletePolicyName,
                this.props._csrf
            )
            .then(() => {
                this.reloadPolicies(
                    `Successfully deleted policy ${this.state.deletePolicyName}`,
                    true
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
            errorMessage: null,
        });
    }

    onClickDeletePolicy(policyName) {
        this.setState({
            showDelete: true,
            deletePolicyName: policyName,
            errorMessage: null,
        });
    }

    componentDidUpdate(prevProps) {
        if (prevProps.policies !== this.props.policies && this.props.role) {
            let filteredPolicies = this.filterPolicies();
            this.setState({
                list: filteredPolicies,
            });
        }
    }

    filterPolicies() {
        const { policies, role } = this.props;
        let filteredPolicies = [];
        if (role) {
            filteredPolicies = policies.filter((policy) => {
                let included = false;
                if (policy.assertions) {
                    for (const [, assertion] of Object.entries(
                        policy.assertions
                    )) {
                        if (
                            NameUtils.getShortName(':role.', assertion.role) ===
                            role
                        ) {
                            included = true;
                        }
                    }
                    return included;
                }
            });
        }
        return filteredPolicies;
    }

    reloadPolicies(successMessage, showSuccess = true) {
        let filteredPolicies = this.filterPolicies();
        this.setState({
            list: filteredPolicies,
            showAddPolicy: false,
            showSuccess,
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
        let rows = '';
        if (this.state.list && this.state.list.length > 0) {
            rows = this.state.list.map((item, i) => {
                let name = NameUtils.getShortName(':policy.', item.name);
                let onClickDeletePolicy = this.onClickDeletePolicy.bind(
                    this,
                    name
                );
                let newPolicy = name === this.state.successMessage;
                return (
                    <RolePolicyRow
                        id={name}
                        name={name}
                        domain={domain}
                        role={role}
                        modified={item.modified}
                        key={item.name}
                        _csrf={this.props._csrf}
                        onClickDeletePolicy={onClickDeletePolicy}
                        newPolicy={newPolicy}
                    />
                );
            });
        } else {
            rows = (
                <tr>
                    <td>There is no policy related to this role</td>
                </tr>
            );
        }

        let addPolicy = this.state.showAddPolicy ? (
            <AddPolicyToRole
                showAddPolicy={this.state.showAddPolicy}
                onCancel={this.toggleAddPolicy}
                onSubmit={this.reloadPolicies}
                domain={domain}
                role={role}
                _csrf={this.props._csrf}
            />
        ) : (
            ''
        );

        return this.props.isLoading.length !== 0 ? (
            <ReduxPageLoader message={'Loading role data'} />
        ) : (
            <PolicySectionDiv data-testid='role-policy-list'>
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

const mapStateToProps = (state, props) => {
    return {
        ...props,
        policies: selectActivePoliciesOnly(state),
        isLoading: selectIsLoading(state),
    };
};

const mapDispatchToProps = (dispatch) => ({
    deletePolicy: (domainName, roleName) =>
        dispatch(deletePolicy(domainName, roleName)),
});

export default connect(mapStateToProps, mapDispatchToProps)(RolePolicyList);
