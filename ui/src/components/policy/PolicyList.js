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
import AddPolicy from './AddPolicy';
import PolicyRow from './PolicyRow';
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
`;

const StyledAnchor = styled.a`
    color: #3570f4;
    text-decoration: none;
    cursor: pointer;
`;

const PolicyTable = styled.table`
    width: 100%;
    border-spacing: 0;
    display: table;
    border-collapse: separate;
    border-color: grey;
`;

const TableHeadStyled = styled.th`
    text-align: ${(props) => props.align};
    border-bottom: 2px solid #d5d5d5;
    color: #9a9a9a;
    font-weight: 600;
    font-size: 0.8rem;
    padding-bottom: 5px;
    vertical-align: top;
    text-transform: uppercase;
    padding: 5px 0 5px 15px;
    word-break: break-all;
`;

export default class PolicyList extends React.Component {
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
        this.api
            .getPolicies(this.props.domain)
            .then((data) => {
                this.setState({
                    list: data,
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
        const { domain } = this.props;
        const left = 'left';
        const center = 'center';
        const rows = this.state.list.map((item, i) => {
            const name = NameUtils.getShortName(':policy.', item.name);
            let color = '';
            if (i % 2 === 0) {
                color = colors.row;
            }
            let onClickDeletePolicy = this.onClickDeletePolicy.bind(this, name);
            return (
                <PolicyRow
                    name={name}
                    domain={domain}
                    modified={item.modified}
                    color={color}
                    api={this.api}
                    key={item.name}
                    _csrf={this.props._csrf}
                    onClickDeletePolicy={onClickDeletePolicy}
                />
            );
        });
        let addPolicy = this.state.showAddPolicy ? (
            <AddPolicy
                showAddPolicy={this.state.showAddPolicy}
                onCancel={this.toggleAddPolicy}
                onSubmit={this.reloadPolicies}
                domain={domain}
                api={this.api}
                _csrf={this.props._csrf}
            />
        ) : (
            ''
        );
        return (
            <PolicySectionDiv data-testid='policylist'>
                <AddContainerDiv>
                    <StyledAnchor onClick={this.toggleAddPolicy}>
                        Add Policy
                    </StyledAnchor>
                    {addPolicy}
                </AddContainerDiv>
                <PolicyTable>
                    <thead>
                        <tr>
                            <TableHeadStyled align={left}>
                                Policy
                            </TableHeadStyled>
                            <TableHeadStyled align={left}>
                                Modified Date
                            </TableHeadStyled>
                            <TableHeadStyled align={center}>
                                Rules
                            </TableHeadStyled>
                            <TableHeadStyled align={center}>
                                Delete
                            </TableHeadStyled>
                        </tr>
                    </thead>
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
