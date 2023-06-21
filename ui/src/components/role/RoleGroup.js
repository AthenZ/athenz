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
import { GROUP_ROLES_CATEGORY } from '../constants/constants';
import RoleSectionRow from './RoleSectionRow';

const LeftMarginSpan = styled.span`
    margin-right: 10px;
    verticalalign: bottom；;
`;

const TDStyled = styled.div`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    vertical-align: middle;
    word-break: break-all;
    width: 100%;
`;

const TrStyled = styled.div`
    box-sizing: border-box;
    margin-top: 5px;
    box-shadow: 0 1px 4px #d9d9d9;
    border: 1px solid #fff;
    -webkit-border-image: none;
    border-image: none;
    -webkit-border-image: initial;
    border-image: initial;
    display: flex;
    padding: 10px 0 10px 0;
`;

const StyledDiv = styled.div`
    padding: 10px 0 10px 0;
    width: 100%;
`;

const StyledPaddingLeft = styled.div`
    padding-left: 20px;
    width: 100%;
`;

export default class RoleGroup extends React.Component {
    constructor(props) {
        super(props);

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
        this.setState({
            expanded: !this.state.expanded,
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
            let label = this.props.name;
            if (this.props.category !== GROUP_ROLES_CATEGORY) {
                label = label.toUpperCase();
            }
            let length = this.state.roles.length;

            if (this.state.expanded) {
                let sectionRows = this.state.roles
                    .sort((a, b) => {
                        if (this.props.category === GROUP_ROLES_CATEGORY) {
                            return a.roleName.localeCompare(b.roleName);
                        } else {
                            return a.name.localeCompare(b.name);
                        }
                    })
                    .map((item, i) => {
                        let color = '';
                        if (i % 2 === 0) {
                            color = colors.row;
                        }
                        let key = '';
                        if (this.props.category === GROUP_ROLES_CATEGORY) {
                            key = item.roleName + '-' + item.domainName;
                        } else {
                            key = item.name;
                        }
                        return (
                            <RoleSectionRow
                                category={this.props.category}
                                details={item}
                                idx={i}
                                color={color}
                                domain={domain}
                                key={key}
                                onUpdateSuccess={this.props.onUpdateSuccess}
                                timeZone={this.props.timeZone}
                                _csrf={this.props._csrf}
                                newRole={this.props.newRole}
                            />
                        );
                    });

                rows.push(
                    <TrStyled key='aws-role-section' data-testid='role-group'>
                        <TDStyled align={left}>
                            <StyledPaddingLeft>
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
                            </StyledPaddingLeft>
                            <StyledDiv>{sectionRows}</StyledDiv>
                        </TDStyled>
                    </TrStyled>
                );
            } else {
                rows.push(
                    <TrStyled key='aws-role-section' data-testid='role-group'>
                        <TDStyled align={left}>
                            <StyledPaddingLeft>
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
                            </StyledPaddingLeft>
                        </TDStyled>
                        <TDStyled align={center} />
                    </TrStyled>
                );
            }

            return rows;
        } else {
            return null;
        }
    }
}
