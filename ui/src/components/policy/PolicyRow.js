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
import Icon from '../denali/icons/Icon';
import { colors } from '../denali/styles';
import styled from '@emotion/styled';
import PolicyRuleTable from './PolicyRuleTable';
import DateUtils from '../utils/DateUtils';
import RequestUtils from '../utils/RequestUtils';

const TdStyled = styled.td`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 15px;
    vertical-align: middle;
    word-break: break-all;
`;

const TrStyled = styled.tr`
    background-color: ${(props) => props.color};
`;

export default class PolicyRow extends React.Component {
    constructor(props) {
        super(props);
        this.api = this.props.api;
        this.toggleAssertions = this.toggleAssertions.bind(this);
        this.state = {
            name: this.props.name,
            errorMessage: null,
        };
        this.localDate = new DateUtils();
    }

    toggleAssertions() {
        if (this.state.assertions) {
            this.setState({ assertions: null });
        } else {
            this.api
                .getPolicy(this.props.domain, this.state.name)
                .then((assertions) => {
                    this.setState({
                        assertions: assertions.assertions,
                        errorMessage: null,
                    });
                })
                .catch((err) => {
                    this.setState({
                        errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                    });
                });
        }
    }

    render() {
        let rows = [];
        let left = 'left';
        let center = 'center';
        rows.push(
            <tr key={this.state.name} data-testid='policy-row'>
                <TdStyled color={this.props.color} align={left}>
                    {this.state.name}
                </TdStyled>
                <TdStyled color={this.props.color} align={left}>
                    {this.localDate.getLocalDate(
                        this.props.modified,
                        'UTC',
                        'UTC'
                    )}
                </TdStyled>
                <TdStyled color={this.props.color} align={center}>
                    <Icon
                        icon={'list-check'}
                        onClick={this.toggleAssertions}
                        color={colors.icons}
                        isLink
                        size={'1.25em'}
                        verticalAlign={'text-bottom'}
                    />
                </TdStyled>
                <TdStyled color={this.props.color} align={center}>
                    <Icon
                        icon={'trash'}
                        onClick={this.props.onClickDeletePolicy}
                        color={colors.icons}
                        isLink
                        size={'1.25em'}
                        verticalAlign={'text-bottom'}
                    />
                </TdStyled>
            </tr>
        );
        if (this.state.assertions) {
            rows.push(
                <TrStyled
                    color={this.props.color}
                    key={this.state.name + '-info'}
                >
                    <PolicyRuleTable
                        color={this.props.color}
                        assertions={this.state.assertions}
                        name={this.state.name}
                        api={this.api}
                        domain={this.props.domain}
                        role={this.props.role}
                        _csrf={this.props._csrf}
                    />
                </TrStyled>
            );
        }
        return rows;
    }
}
