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
import Icon from '../denali/icons/Icon';
import { colors } from '../denali/styles';
import { withRouter } from 'next/router';

const DomainListDiv = styled.div`
    padding: 0 30px 0 15px;
`;

const DomainDiv = styled.div`
    padding: 10px 0;
    display: flex;
`;

const UserAdminLogoDiv = styled.div`
    font-size: 1.25em;
    margin-right: 5px;
`;

const StyledAnchor = styled.a`
    color: ${(props) => (props.active ? colors.black : colors.linkActive)};
    text-decoration: none;
    cursor: pointer;
    font-weight: ${(props) => (props.active ? 600 : '')};
`;

const ShowDomainsDiv = styled.div`
    margin-right: 0;
    border-left: 1px solid #d5d5d5;
    flex: 0 0 350px;
    height: calc(100vh - 60px);
    overflow: auto;
    transition: margin 0.4s ease-in-out;
    display: block;
    min-width: 350px;
    width: 350px;
`;

const ToggleBoxDiv = styled.div`
    align-items: center;
    background-color: #fff;
    border-bottom: 1px solid #d5d5d5;
    border-left: 1px solid #d5d5d5;
    border-top: 1px solid #d5d5d5;
    cursor: pointer;
    display: flex;
    height: 20px;
    justify-content: center;
    margin-left: -21px;
    margin-top: 20px;
    position: absolute;
    text-align: center;
    width: 20px;
`;

const ManageDomainsHeaderDiv = styled.div`
    align-items: baseline;
    display: flex;
    flex-flow: row nowrap;
    justify-content: space-between;
    padding: 20px 30px 20px 15px;
`;

const ManageDomainsTitleDiv = styled.div`
    font-size: 16px;
    font-weight: 600;
`;

const DividerSpan = styled.span`
    padding: 0 5px;
    color: ${colors.grey500};
`;

class UserDomains extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.toggleDomains = this.toggleDomains.bind(this);
        this.state = {
            showDomains: !(props.hideDomains ? props.hideDomains : false),
        };
    }

    toggleDomains() {
        this.setState({
            showDomains: !this.state.showDomains,
        });
    }

    routeHandler = (route) => (e) => {
        e.preventDefault();
        this.props.router.push(route, route, { getInitialProps: true });
    };

    render() {
        let userIcons = [];
        let currentDomain = this.props.domain ? this.props.domain : null;
        if (this.props.domains && this.props.domains.length > 0) {
            this.props.domains.forEach((domain) => {
                const domainName = domain.name;
                let iconType = domain.adminDomain
                    ? 'user-secure'
                    : 'user-group';
                userIcons.push(
                    <DomainDiv key={domainName}>
                        <UserAdminLogoDiv>
                            <Icon
                                size={'1em'}
                                icon={iconType}
                                color={colors.black}
                                verticalAlign={'baseline'}
                            />
                        </UserAdminLogoDiv>
                        <StyledAnchor
                            active={currentDomain === domainName}
                            onClick={this.routeHandler(
                                `/domain/${domainName}/role`
                            )}
                        >
                            {domainName}
                        </StyledAnchor>
                    </DomainDiv>
                );
            });
        }
        let arrow = (
            <Icon size={'1em'} icon={'arrow-left'} color={colors.black} />
        );
        if (this.state.showDomains) {
            arrow = (
                <Icon size={'1em'} icon={'arrow-right'} color={colors.black} />
            );
        }
        return (
            <div data-testid='user-domains'>
                <ToggleBoxDiv
                    onClick={this.toggleDomains}
                    data-testid='toggle-domain'
                >
                    {arrow}
                </ToggleBoxDiv>
                {this.state.showDomains && (
                    <ShowDomainsDiv>
                        <ManageDomainsHeaderDiv>
                            <ManageDomainsTitleDiv>
                                My Domains
                            </ManageDomainsTitleDiv>
                            <div>
                                <StyledAnchor
                                    onClick={this.routeHandler(
                                        `/domain/create`
                                    )}
                                >
                                    Create
                                </StyledAnchor>
                                <DividerSpan> | </DividerSpan>
                                <StyledAnchor
                                    onClick={this.routeHandler(
                                        `/domain/manage`
                                    )}
                                >
                                    Manage
                                </StyledAnchor>
                            </div>
                        </ManageDomainsHeaderDiv>
                        <DomainListDiv>{userIcons}</DomainListDiv>
                    </ShowDomainsDiv>
                )}
            </div>
        );
    }
}
export default withRouter(UserDomains);
