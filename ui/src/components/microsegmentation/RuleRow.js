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
import Icon from '../denali/icons/Icon';
import { colors } from '../denali/styles';
import styled from '@emotion/styled';
import DeleteModal from '../modal/DeleteModal';
import Menu from '../denali/Menu/Menu';
import DateUtils from '../utils/DateUtils';
import RequestUtils from '../utils/RequestUtils';
import ServiceList from './ServiceList';
import { css, keyframes } from '@emotion/react';
import EnforcementStateList from './EnforcementStateList';
import AddSegmentation from './AddSegmentation';

const TDStyled = styled.td`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 15px;
    vertical-align: middle;
    word-break: break-all;
`;

const GroupTDStyled = styled.td`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 15px;
    vertical-align: middle;
    word-break: break-all;
    text-decoration: dashed underline;
`;

const colorTransition = keyframes`
        0% {
            background-color: rgba(21, 192, 70, 0.20);
        }
        100% {
            background-color: transparent;
        }
`;

const TrStyled = styled.tr`
    ${(props) =>
        props.isSuccess &&
        css`
            animation: ${colorTransition} 3s ease;
        `}
`;

const MenuDiv = styled.div`
    padding: 5px 10px;
    background-color: black;
    color: white;
    font-size: 12px;
`;

export default class RuleRow extends React.Component {
    constructor(props) {
        super(props);
        this.api = this.props.api;
        this.onSubmitDelete = this.onSubmitDelete.bind(this);
        this.onClickDeleteCancel = this.onClickDeleteCancel.bind(this);
        this.onClickDeleteCondition = this.onClickDeleteCondition.bind(this);
        this.onClickEditCancel = this.onClickEditCancel.bind(this);
        this.onClickEditSubmit = this.onClickEditSubmit.bind(this);
        this.onClickEdit = this.onClickEdit.bind(this);
        this.saveJustification = this.saveJustification.bind(this);
        this.state = {
            deleteName:
                this.props.category === 'inbound'
                    ? this.props.details['destination_service']
                    : this.props.details['source_service'],
            showDelete: false,
            assertionId: this.props.details['assertionIdx'],
            port: '',
            showDeleteAssertionCondition: false,
            policyName: '',
            conditionId: '',
            justification: '',
            showEditSegmentation: false,
        };
        this.localDate = new DateUtils();
    }

    saveJustification(val) {
        this.setState({ justification: val });
    }

    onClickDelete(name, id, port) {
        this.setState({
            showDelete: true,
            deleteName: name,
            assertionId: id,
            port: port,
        });
    }

    onClickDeleteCondition(assertionId, conditionId, policyName) {
        this.setState({
            showDeleteAssertionCondition: true,
            policyName: policyName,
            assertionId: assertionId,
            conditionId: conditionId,
        });
    }

    onClickEdit() {
        this.setState({
            showEditSegmentation: true,
        });
    }

    onClickEditCancel() {
        this.setState({
            showEditSegmentation: false,
        });
    }

    onClickEditSubmit() {
        this.setState({
            showEditSegmentation: false,
        });
        this.props.onUpdateSuccess();
    }

    onSubmitDelete(domain) {
        if (
            this.props.justificationRequired &&
            (this.state.justification === undefined ||
                this.state.justification.trim() === '')
        ) {
            this.setState({
                errorMessage: 'Justification is required to delete ACL Policy.',
            });
            return;
        }

        let deletePolicyName =
            'acl.' + this.state.deleteName + '.' + this.props.category;
        let deleteRoleName =
            deletePolicyName + '-' + this.props.details['identifier'];
        Promise.all([
            this.api.deleteAssertion(
                domain,
                deletePolicyName,
                this.state.assertionId,
                this.state.justification
                    ? this.state.justification
                    : 'Micro-segmentaion assertion deletion',
                this.props._csrf
            ),
            this.api.deleteRole(
                domain,
                deleteRoleName,
                this.state.justification
                    ? this.state.justification
                    : 'Micro-segmentaion Role deletion',
                this.props._csrf
            ),
        ])
            .then(() => {
                this.setState({
                    showDelete: false,
                });
                this.props.onUpdateSuccess();
            })
            .catch((err) => {
                if (err.statusCode === 404) {
                    this.setState({
                        showDelete: false,
                    });
                    this.props.onUpdateSuccess();
                } else {
                    this.setState({
                        errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                    });
                }
            });
    }

    onClickDeleteCancel() {
        this.setState({
            showDelete: false,
            deleteName: '',
            errorMessage: null,
        });
    }

    onSubmitDeleteCondition() {
        if (
            this.props.justificationRequired &&
            (this.state.justification === undefined ||
                this.state.justification.trim() === '')
        ) {
            this.setState({
                errorMessage:
                    'Justification is required to delete Policy Enforcement Condition.',
            });
            return;
        }

        this.api
            .deleteAssertionCondition(
                this.props.domain,
                this.state.policyName,
                this.state.assertionId,
                this.state.conditionId,
                this.state.justification
                    ? this.state.justification
                    : 'Micro-segmentaion Assertion Condition deletion',
                this.props._csrf
            )
            .then(() => {
                this.setState({
                    showDeleteAssertionCondition: false,
                    errorMessage: null,
                });
                this.props.onUpdateSuccess();
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    onClickDeleteConditionCancel() {
        this.setState({
            showDeleteAssertionCondition: false,
            errorMessage: null,
        });
    }

    render() {
        let rows = [];
        let left = 'left';
        let center = 'center';
        let data = this.props.details;
        let color = this.props.color;
        let key = '';
        let submitDelete = this.onSubmitDelete.bind(this, this.props.domain);
        let submitDeleteCondition = this.onSubmitDeleteCondition.bind(this);
        let clickDeleteCancel = this.onClickDeleteCancel.bind(this);
        let clickDeleteConditionCancel =
            this.onClickDeleteConditionCancel.bind(this);
        let inbound = this.props.category === 'inbound';
        let clickDelete;
        if (inbound) {
            key =
                this.props.category +
                data.destination_service +
                data.destination_port +
                this.props.idx;
            clickDelete = this.onClickDelete.bind(
                this,
                this.state.deleteName,
                this.state.assertionId,
                data.destination_port
            );
        } else {
            key =
                this.props.category +
                data.source_service +
                data.source_port +
                this.props.idx;
            clickDelete = this.onClickDelete.bind(
                this,
                this.state.deleteName,
                this.state.assertionId,
                data.source_port
            );
        }

        let editData = this.props.details;
        editData['category'] = this.props.category;
        let addSegmentation = this.state.showEditSegmentation ? (
            <AddSegmentation
                api={this.api}
                domain={this.props.domain}
                onSubmit={this.onClickEditSubmit}
                onCancel={this.onClickEditCancel}
                _csrf={this.props._csrf}
                showAddSegment={this.state.showEditSegmentation}
                justificationRequired={this.props.justificationRequired}
                editMode={true}
                data={editData}
            />
        ) : (
            ''
        );

        rows.push(
            <TrStyled key={key} data-testid='segmentation-row'>
                <TDStyled color={color} align={left}>
                    {data['identifier']}
                </TDStyled>

                {inbound && (
                    <TDStyled color={color} align={left}>
                        {data['destination_service']}
                    </TDStyled>
                )}
                {!inbound && (
                    <TDStyled color={color} align={left}>
                        {data['source_service']}
                    </TDStyled>
                )}

                {inbound && (
                    <TDStyled color={color} align={left}>
                        {data['destination_port']}
                    </TDStyled>
                )}
                {!inbound && (
                    <TDStyled color={color} align={left}>
                        {data['source_port']}
                    </TDStyled>
                )}

                <GroupTDStyled color={color} align={left}>
                    <Menu
                        placement='right'
                        boundary='scrollParent'
                        trigger={
                            <span>
                                <Icon
                                    icon={'service-setting'}
                                    color={colors.icons}
                                    isLink
                                    size={'1.25em'}
                                    verticalAlign={'text-bottom'}
                                />
                            </span>
                        }
                    >
                        {inbound && (
                            <ServiceList
                                list={data['source_services']}
                                api={this.api}
                                domain={this.props.domain}
                            />
                        )}
                        {!inbound && (
                            <ServiceList
                                list={data['destination_services']}
                                api={this.api}
                                domain={this.props.domain}
                            />
                        )}
                    </Menu>
                </GroupTDStyled>

                {inbound && (
                    <TDStyled color={color} align={left}>
                        {data['source_port']}
                    </TDStyled>
                )}
                {!inbound && (
                    <TDStyled color={color} align={left}>
                        {data['destination_port']}
                    </TDStyled>
                )}

                <TDStyled color={color} align={left}>
                    {data['layer']}
                </TDStyled>

                <GroupTDStyled color={color} align={center}>
                    <Menu
                        placement='right'
                        boundary='scrollParent'
                        triggerOn='click'
                        trigger={
                            <span>
                                <Icon
                                    icon={
                                        this.props.category === 'inbound'
                                            ? 'network-resource'
                                            : 'network-role'
                                    }
                                    color={colors.icons}
                                    isLink
                                    size={'1.25em'}
                                    verticalAlign={'text-bottom'}
                                />
                            </span>
                        }
                    >
                        <EnforcementStateList
                            list={data['conditionsList']}
                            api={this.api}
                            domain={this.props.domain}
                            _csrf={this.props._csrf}
                            deleteCondition={this.onClickDeleteCondition}
                        />
                    </Menu>
                </GroupTDStyled>
                <TDStyled color={color} align={center}>
                    <Menu
                        placement='bottom-start'
                        trigger={
                            <span>
                                <Icon
                                    icon={'pencil'}
                                    onClick={this.onClickEdit}
                                    color={colors.icons}
                                    isLink
                                    size={'1.25em'}
                                    verticalAlign={'text-bottom'}
                                />
                            </span>
                        }
                    >
                        <MenuDiv>Edit Rule</MenuDiv>
                    </Menu>
                </TDStyled>
                {addSegmentation}
                <TDStyled color={color} align={center}>
                    <Menu
                        placement='bottom-start'
                        trigger={
                            <span>
                                <Icon
                                    icon={'trash'}
                                    onClick={clickDelete}
                                    color={colors.icons}
                                    isLink
                                    size={'1.25em'}
                                    verticalAlign={'text-bottom'}
                                />
                            </span>
                        }
                    >
                        <MenuDiv>Delete Rule</MenuDiv>
                    </Menu>
                </TDStyled>
            </TrStyled>
        );

        if (this.state.showDelete) {
            rows.push(
                <DeleteModal
                    name={this.props.details['source_service']}
                    isOpen={this.state.showDelete}
                    cancel={clickDeleteCancel}
                    submit={submitDelete}
                    key={this.props.details['source_service'] + '-delete'}
                    message={
                        'Are you sure you want to permanently delete the ' +
                        this.props.category +
                        ' rule '
                    }
                    errorMessage={this.state.errorMessage}
                    showJustification={this.props.justificationRequired}
                    onJustification={this.saveJustification}
                />
            );
        }

        if (this.state.showDeleteAssertionCondition) {
            rows.push(
                <DeleteModal
                    isOpen={this.state.showDeleteAssertionCondition}
                    cancel={clickDeleteConditionCancel}
                    submit={submitDeleteCondition}
                    key={
                        this.state.assertionId +
                        '-' +
                        this.state.conditionId +
                        '-delete'
                    }
                    message={
                        'Are you sure you want to permanently delete the Policy Enforcement Condition'
                    }
                    errorMessage={this.state.errorMessage}
                    showJustification={this.props.justificationRequired}
                    onJustification={this.saveJustification}
                />
            );
        }

        return rows;
    }
}
