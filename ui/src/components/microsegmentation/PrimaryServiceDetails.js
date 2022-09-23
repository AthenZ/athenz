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
import { css } from '@emotion/react';
import EnforcementStateList from './EnforcementStateList';
import DeleteModal from '../modal/DeleteModal';
import RequestUtils from '../utils/RequestUtils';
import {
    DESTINATION_PORTS_LABEL,
    IDENTIFIER_LABEL,
    MICROSEG_CONDITION_DELETE_JUSTIFICATION,
    PROTOCOL_LABEL,
    SOURCE_PORTS_LABEL,
} from '../constants/constants';
import { deleteAssertionCondition } from '../../redux/thunks/policies';
import { connect } from 'react-redux';

const StyledDiv = styled.div`
    display: flex;
    flex-direction: column;
    background: rgb(248, 248, 248);
    border: 1px solid rgb(213, 213, 213);
    border-radius: 3px;
`;

const StyledPortIdDiv = styled.div`
    display: flex;
    flex-direction: row;
    padding: 10px;
`;

const StyledProtocolValidationDiv = styled.div`
    display: flex;
    flex-direction: row;
    padding: 10px;
`;

const StyledColumnFlexDiv = styled.div`
    display: flex;
    flex-direction: column;
    flex-grow: 1;
`;

const StyledLabelDiv = styled.div`
    font-size: x-small;
    color: rgb(96, 96, 96);
    text-transform: uppercase;
`;

const StyledDataDiv = styled.div`
    color: rgb(48, 48, 48);
    font-size: small;
`;

class PrimaryServiceDetails extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.onClickDeleteConditionCancel =
            this.onClickDeleteConditionCancel.bind(this);
        this.onClickDeleteCondition = this.onClickDeleteCondition.bind(this);
        this.onSubmitDeleteCondition = this.onSubmitDeleteCondition.bind(this);
        this.state = {
            showDeleteAssertionCondition: false,
        };
    }

    onClickDeleteCondition(assertionId, conditionId, policyName) {
        this.setState({
            showDeleteAssertionCondition: true,
            policyName: policyName,
            assertionId: assertionId,
            conditionId: conditionId,
        });
    }

    onClickDeleteConditionCancel() {
        this.setState({
            showDeleteAssertionCondition: false,
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
        this.props
            .deleteAssertionCondition(
                this.props.domain,
                this.state.policyName,
                this.state.assertionId,
                this.state.conditionId,
                this.state.justification
                    ? this.state.justification
                    : MICROSEG_CONDITION_DELETE_JUSTIFICATION,
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

    render() {
        const { data } = this.props;
        let onClickDeleteCondition = this.onClickDeleteCondition.bind(this);
        let submitDeleteCondition = this.onSubmitDeleteCondition.bind(this);
        let clickDeleteConditionCancel =
            this.onClickDeleteConditionCancel.bind(this);
        let rows = [];

        let portLabel, ports;

        if (data['category'] === 'inbound') {
            portLabel = DESTINATION_PORTS_LABEL;
            ports = data['destination_port'];
        } else {
            portLabel = SOURCE_PORTS_LABEL;
            ports = data['source_port'];
        }

        rows.push(
            <StyledDiv category={data['category']}>
                <StyledPortIdDiv>
                    <StyledColumnFlexDiv>
                        <StyledLabelDiv>{portLabel}</StyledLabelDiv>
                        <StyledDataDiv>{ports}</StyledDataDiv>
                    </StyledColumnFlexDiv>
                    <StyledColumnFlexDiv>
                        <StyledLabelDiv>{IDENTIFIER_LABEL}</StyledLabelDiv>
                        <StyledDataDiv>{data['identifier']}</StyledDataDiv>
                    </StyledColumnFlexDiv>
                </StyledPortIdDiv>
                <StyledProtocolValidationDiv>
                    <StyledColumnFlexDiv>
                        <StyledLabelDiv>{PROTOCOL_LABEL}</StyledLabelDiv>
                        <StyledDataDiv>{data['layer']}</StyledDataDiv>
                    </StyledColumnFlexDiv>
                </StyledProtocolValidationDiv>
                <hr />
                <EnforcementStateList
                    list={data['conditionsList']}
                    api={this.props.api}
                    domain={this.props.domain}
                    _csrf={this.props._csrf}
                    deleteCondition={onClickDeleteCondition}
                />
            </StyledDiv>
        );

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

const mapDispatchToProps = (dispatch) => ({
    deleteAssertionCondition: (
        domain,
        policyName,
        assertionId,
        conditionId,
        auditRef,
        _csrf
    ) =>
        dispatch(
            deleteAssertionCondition(
                domain,
                policyName,
                assertionId,
                conditionId,
                auditRef,
                _csrf
            )
        ),
});

export default connect(null, mapDispatchToProps)(PrimaryServiceDetails);
