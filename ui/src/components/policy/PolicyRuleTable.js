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
import Icon from '../denali/icons/Icon';
import { colors } from '../denali/styles';
import AddAssertion from './AddAssertion';
import Alert from '../denali/Alert';
import DeleteModal from '../modal/DeleteModal';
import {
    DELETE_AUDIT_REFERENCE,
    DISPLAY_SPACE,
    MODAL_TIME_OUT,
} from '../constants/constants';
import RequestUtils from '../utils/RequestUtils';
import { css, keyframes } from '@emotion/react';
import NameUtils from '../utils/NameUtils';
import {
    deleteAssertionPolicyVersion,
    getPolicyVersion,
} from '../../redux/thunks/policies';
import { connect } from 'react-redux';

const StyleTable = styled.table`
    width: 100%;
    border-spacing: 0;
    display: table;
    border-collapse: separate;
`;

const StyleTd = styled.td`
    padding: 30px 20px;
    background-color: ${(props) => props.color};
`;

const RuleHeadStyled = styled.th`
    border-bottom: 2px solid #d5d5d5;
    color: #9a9a9a;
    font-weight: 600;
    font-size: 1.2rem;
    padding-bottom: 5px;
    vertical-align: top;
    text-transform: uppercase;
    padding: 5px 0 5px 15px;
    text-align: left;
    background-color: white;
`;

const IconHeadStyled = styled.th`
    border-bottom: 2px solid #d5d5d5;
    color: #9a9a9a;
    font-weight: 600;
    padding-bottom: 5px;
    vertical-align: top;
    text-transform: uppercase;
    width: 120px;
    text-align: center;
    background-color: white;
`;

const TableHeadStyled = styled.th`
    text-align: ${(props) => props.align};
    border-bottom: 2px solid #d5d5d5;
    color: ${(props) => props.color};
    font-weight: ${(props) => props.weight};
    font-size: ${(props) => props.size};
    padding-bottom: 2px;
    vertical-align: top;
    padding: 10px 10px 0px 15px;
    word-break: break-all;
`;

const TableDiv = styled.div`
    margin: 15px 0 0 0;
`;

const TDStyled = styled.td`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 15px;
    vertical-align: middle;
    word-break: break-all;
`;

const StyledAnchor = styled.a`
    color: #3570f4;
    text-decoration: none;
    cursor: pointer;
`;

const TrStyled = styled.tr`
    ${(props) =>
        props.isSuccess &&
        css`
            animation: ${colorTransition} 3s ease;
        `}
    ${(props) =>
        !props.isSuccess &&
        css`
            background-color: white;
        `}
`;

const colorTransition = keyframes`
        0% {
            background-color: rgba(21, 192, 70, 0.20);
        }
        100% {
            background-color: white;
        }
`;

class PolicyRuleTable extends React.Component {
    constructor(props) {
        super(props);
        this.toggleAddAssertion = this.toggleAddAssertion.bind(this);
        this.reLoadAssertions = this.reLoadAssertions.bind(this);
        this.onSubmitDeleteAssertion = this.onSubmitDeleteAssertion.bind(this);
        this.onCancelDeleteAssertion = this.onCancelDeleteAssertion.bind(this);
        this.closeModal = this.closeModal.bind(this);
        this.state = {
            addAssertion: false,
            assertions: this.props.assertions ? this.props.assertions : [],
            showDelete: false,
        };
    }

    toggleAddAssertion() {
        this.setState({ addAssertion: !this.state.addAssertion });
    }

    reLoadAssertions(successMessage, showSuccess) {
        this.props
            .getPolicyVersion(
                this.props.domain,
                this.props.name,
                this.props.version
            )
            .then((policy) => {
                this.setState({
                    assertions: policy.assertions,
                    addAssertion: false,
                    successMessage,
                    showDelete: false,
                    showSuccess,
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
        this.setState({ showSuccess: false });
    }

    onClickDeleteAssertion(role, assertionId) {
        this.setState({
            showDelete: true,
            deleteAssertionRole: role,
            deleteAssertionId: assertionId,
            errorMessage: null,
        });
    }

    onSubmitDeleteAssertion() {
        this.props
            .deleteAssertionPolicyVersion(
                this.props.domain,
                this.props.name,
                this.props.version,
                this.state.deleteAssertionId,
                this.props._csrf
            )
            .then(() => {
                this.reLoadAssertions(
                    `Successfully deleted assertion from policy ${this.props.name} version ${this.props.version}`
                );
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    onCancelDeleteAssertion() {
        this.setState({
            showDelete: false,
            deleteAssertionRole: null,
            deleteAssertionId: null,
            errorMessage: null,
        });
    }

    render() {
        let rows = [];
        const left = 'left';
        const center = 'center';
        const right = 'right';
        this.state.assertions.forEach((assertion, i) => {
            let onClickDeleteAssertion = this.onClickDeleteAssertion.bind(
                this,
                assertion.role,
                assertion.id
            );
            let tempRole = NameUtils.getShortName(
                this.props.domain + ':role.',
                assertion.role
            );
            let tempResource = NameUtils.getShortName(
                this.props.domain + ':',
                assertion.resource
            );
            let newAssertion =
                this.props.name +
                    '-' +
                    this.props.version +
                    '-' +
                    tempRole +
                    '-' +
                    tempResource +
                    '-' +
                    assertion.action ===
                this.state.successMessage;
            rows.push(
                <TrStyled
                    key={
                        this.props.name +
                        '-' +
                        this.props.version +
                        i +
                        '-assertion'
                    }
                    isSuccess={newAssertion}
                >
                    <TDStyled align={left}>{assertion.effect}</TDStyled>
                    <TDStyled align={left}>
                        {assertion.action.replace(/\s/g, DISPLAY_SPACE)}
                    </TDStyled>
                    <TDStyled align={left}>{assertion.role}</TDStyled>
                    <TDStyled align={left}>{assertion.resource}</TDStyled>
                    <TDStyled align={center}>
                        <Icon
                            icon={'trash'}
                            onClick={onClickDeleteAssertion}
                            color={colors.icons}
                            isLink
                            size={'1.25em'}
                            verticalAlign={'text-bottom'}
                        />
                    </TDStyled>
                </TrStyled>
            );
        });
        let addAssertion = '';
        if (this.state.addAssertion) {
            addAssertion = (
                <AddAssertion
                    domain={this.props.domain}
                    cancel={this.toggleAddAssertion}
                    submit={this.reLoadAssertions}
                    _csrf={this.props._csrf}
                    name={this.props.name}
                    version={this.props.version}
                />
            );
        }
        return (
            <StyleTd
                colSpan={7}
                backgroundColor={'black'}
                data-testid='ruletable'
            >
                <StyleTable data-testid='ruledetailstable'>
                    <tbody>
                        <tr>
                            <TableHeadStyled
                                align={left}
                                size={'16px'}
                                weight={600}
                                color={'#303030'}
                            >
                                Rule Details({this.props.assertions.length})
                            </TableHeadStyled>
                            <TableHeadStyled
                                align={right}
                                color={'#3570F4'}
                                weight={300}
                                size={'14px'}
                                onClick={this.toggleAddAssertion}
                            >
                                <StyledAnchor>Add rule</StyledAnchor>
                            </TableHeadStyled>
                        </tr>
                        <tr>
                            <td colSpan={7}>{addAssertion}</td>
                        </tr>
                        <tr>
                            <td colSpan={7}>
                                <TableDiv>
                                    <StyleTable>
                                        <thead>
                                            <tr>
                                                <RuleHeadStyled>
                                                    Effect
                                                </RuleHeadStyled>
                                                <RuleHeadStyled>
                                                    Action
                                                </RuleHeadStyled>
                                                <RuleHeadStyled>
                                                    Role
                                                </RuleHeadStyled>
                                                <RuleHeadStyled>
                                                    Resource
                                                </RuleHeadStyled>
                                                <IconHeadStyled />
                                            </tr>
                                        </thead>
                                        <tbody>{rows}</tbody>
                                    </StyleTable>
                                </TableDiv>
                            </td>
                        </tr>
                    </tbody>
                </StyleTable>
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
                        name={this.state.deleteAssertionRole}
                        isOpen={this.state.showDelete}
                        cancel={this.onCancelDeleteAssertion}
                        submit={this.onSubmitDeleteAssertion}
                        errorMessage={this.state.errorMessage}
                        message={
                            'Are you sure you want to permanently delete the assertion with Role '
                        }
                    />
                ) : null}
            </StyleTd>
        );
    }
}

const mapDispatchToProps = (dispatch) => ({
    getPolicyVersion: (domain, policy, version) =>
        dispatch(getPolicyVersion(domain, policy, version)),
    deleteAssertionPolicyVersion: (
        domain,
        policyName,
        policyVersion,
        deleteAssertionId,
        _csrf
    ) =>
        dispatch(
            deleteAssertionPolicyVersion(
                domain,
                policyName,
                policyVersion,
                deleteAssertionId,
                DELETE_AUDIT_REFERENCE,
                _csrf
            )
        ),
});

export default connect(null, mapDispatchToProps)(PolicyRuleTable);
