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
import RolePolicyRuleTable from './RolePolicyRuleTable';
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
    box-sizing: border-box;
    margin-top: 10px;
    box-shadow: 0 1px 4px #d9d9d9;
    border: 1px solid #fff;
    -webkit-border-image: none;
    border-image: none;
    -webkit-border-image: initial;
    border-image: initial;
    height: 50px;
`;

const LeftMarginSpan = styled.span`
    margin-right: 10px;
    verticalAlign：bottom；
`;

const StyledDiv = styled.div`
    padding: 10px 0 10px 0;
    width: 100%;
`;

const StyledTable = styled.table`
    width: 100%;
`;

export default class RolePolicyRow extends React.Component {
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
        const arrowup = 'arrowhead-up-circle-solid';
        const arrowdown = 'arrowhead-down-circle';

        if (this.state.assertions) {
            rows.push(
                <TrStyled key={this.state.name} data-testid='policy-row'>
                    <TdStyled align={left}>
                        <StyledDiv>
                            <LeftMarginSpan>
                                <Icon
                                    icon={
                                        this.state.assertions
                                            ? arrowup
                                            : arrowdown
                                    }
                                    onClick={this.toggleAssertions}
                                    color={colors.icons}
                                    isLink
                                    size={'1.25em'}
                                    verticalAlign={'text-bottom'}
                                />
                            </LeftMarginSpan>
                            {this.state.name}
                        </StyledDiv>
                        <StyledDiv>
                            <RolePolicyRuleTable
                                assertions={this.state.assertions}
                                name={this.state.name}
                                api={this.api}
                                domain={this.props.domain}
                                role={this.props.role}
                                _csrf={this.props._csrf}
                            />
                        </StyledDiv>
                    </TdStyled>
                </TrStyled>
            );
        } else {
            rows.push(
                <TrStyled key={this.state.name} data-testid='role-policy-row'>
                    <TdStyled align={left}>
                        <LeftMarginSpan>
                            <Icon
                                icon={
                                    this.state.assertions ? arrowup : arrowdown
                                }
                                onClick={this.toggleAssertions}
                                color={colors.icons}
                                isLink
                                size={'1.25em'}
                                verticalAlign={'text-bottom'}
                            />
                        </LeftMarginSpan>
                        {this.state.name}
                    </TdStyled>
                </TrStyled>
            );
        }
        return rows;
    }
}
