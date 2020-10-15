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
import RoleSectionRow from './RoleSectionRow';
import Icon from '../denali/icons/Icon';
import { colors } from '../denali/styles';

const LeftMarginSpan = styled.span`
    margin-right: 10px;
    verticalAlign：bottom；
`;

const TDStyled = styled.td`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 15px;
    vertical-align: middle;
    word-break: break-all;
`;

const TrStyled = styled.tr`
    box-sizing: border-box;
    margin-top: 5px;
    box-shadow: 0 1px 4px #d9d9d9;
    border: 1px solid #fff;
    -webkit-border-image: none;
    border-image: none;
    -webkit-border-image: initial;
    border-image: initial;
    height: 50px;
`;

const StyledDiv = styled.div`
    padding: 10px 0 10px 0;
    width: 100%;
`;

const StyledTable = styled.table`
    width: 100%;
`;

export default class RoleGroup extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;

        this.state = {
            expanded: false,
            roles: props.roles || [],
        };
    }

    componentDidUpdate = (prevProps) => {
        if (prevProps.domain !== this.props.domain) {
            this.setState({
                expanded: false,
                roles: this.props.roles || [],
            });
        } else if (prevProps.roles !== this.props.roles) {
            this.setState({
                roles: this.props.roles || [],
            });
        }
    };

    expandRole() {
        let expanded = this.state.expanded;
        this.setState({
            expanded: !expanded,
        });
    }

    render() {
        const center = 'center';
        const left = 'left';
        const { domain } = this.props;
        const arrowup = 'arrowhead-up-circle-solid';
        const arrowdown = 'arrowhead-down-circle';
        let expandRole = this.expandRole.bind(this);
        let rows = [];

        if (this.state.roles && this.state.roles.length > 0) {
            let label = this.props.name.toUpperCase();
            let length = this.state.roles.length;

            if (this.state.expanded) {
                let sectionRows = this.state.roles.map((item, i) => {
                    let color = '';
                    if (i % 2 === 0) {
                        color = colors.row;
                    }
                    return (
                        <RoleSectionRow
                            api={this.api}
                            details={item}
                            idx={i}
                            color={color}
                            domain={domain}
                            key={item.name}
                            onUpdateSuccess={this.props.onUpdateSuccess}
                            _csrf={this.props._csrf}
                            justificationRequired={
                                this.props.justificationRequired
                            }
                            userProfileLink={this.props.userProfileLink}
                        />
                    );
                });

                rows.push(
                    <TrStyled key='aws-role-section'>
                        <TDStyled align={left} colSpan='8'>
                            <StyledDiv>
                                <LeftMarginSpan>
                                    <Icon
                                        icon={
                                            this.state.expanded
                                                ? arrowup
                                                : arrowdown
                                        }
                                        onClick={expandRole}
                                        color={colors.icons}
                                        isLink
                                        size={'1.25em'}
                                        verticalAlign={'text-bottom'}
                                    />
                                </LeftMarginSpan>
                                {`${label} Roles (${length})`}
                            </StyledDiv>
                            <StyledDiv>
                                <StyledTable>{sectionRows}</StyledTable>
                            </StyledDiv>
                        </TDStyled>
                    </TrStyled>
                );
            } else {
                rows.push(
                    <TrStyled key='aws-role-section'>
                        <TDStyled align={left}>
                            <LeftMarginSpan>
                                <Icon
                                    icon={
                                        this.state.expanded
                                            ? arrowup
                                            : arrowdown
                                    }
                                    onClick={expandRole}
                                    color={colors.icons}
                                    isLink
                                    size={'1.25em'}
                                    verticalAlign={'text-bottom'}
                                />
                            </LeftMarginSpan>
                            {`${label} Roles (${length})`}
                        </TDStyled>
                        <TDStyled align={center} />
                    </TrStyled>
                );
            }

            return rows;
        } else {
            return <div />;
        }
    }
}
