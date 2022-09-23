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
import DateUtils from '../utils/DateUtils';
import { css, keyframes } from '@emotion/react';
import { selectPolicyAssertions } from '../../redux/selectors/policies';
import { deletePolicy } from '../../redux/thunks/policies';
import { connect } from 'react-redux';
import RolePolicyRuleTable from './RolePolicyRuleTable';

const TdStyled = styled.td`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 15px;
    vertical-align: middle;
    word-break: break-all;
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

const TrStyledExpanded = styled.tr`
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
    vertical-align: bottom;
`;

const StyledDiv = styled.div`
    padding: 10px 0 10px 0;
    width: 100%;
`;

class RolePolicyRow extends React.Component {
    constructor(props) {
        super(props);
        this.toggleAssertions = this.toggleAssertions.bind(this);
        this.state = {
            name: this.props.name,
            errorMessage: null,
            newPolicy: this.props.newPolicy,
        };
        this.localDate = new DateUtils();
    }

    toggleAssertions() {
        this.setState({
            assertions: !this.state.assertions,
            newPolicy: false,
        });
    }

    render() {
        let rows = [];
        let left = 'left';
        const arrowup = 'arrowhead-up-circle-solid';
        const arrowdown = 'arrowhead-down-circle';
        let id = this.props.id;
        if (this.state.assertions) {
            rows.push(
                <TrStyledExpanded
                    key={this.state.name + id}
                    data-testid='policy-row'
                >
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
                                id={id}
                                name={this.state.name}
                                domain={this.props.domain}
                                role={this.props.role}
                                _csrf={this.props._csrf}
                            />
                        </StyledDiv>
                    </TdStyled>
                </TrStyledExpanded>
            );
        } else {
            rows.push(
                <TrStyled
                    key={this.state.name}
                    data-testid='role-policy-row'
                    isSuccess={this.state.newPolicy}
                >
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

const mapStateToProps = (state, props) => {
    return {
        ...props,
        assertions: selectPolicyAssertions(state, props.domain, props.name),
    };
};

const mapDispatchToProps = (dispatch) => ({
    deletePolicy: (domainName, roleName) =>
        dispatch(deletePolicy(domainName, roleName)),
});

export default connect(mapStateToProps, mapDispatchToProps)(RolePolicyRow);
