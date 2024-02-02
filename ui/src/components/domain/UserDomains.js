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
import Link from 'next/link';
import { withRouter } from 'next/router';
import PageUtils from '../utils/PageUtils';
import { connect } from 'react-redux';
import { getUserDomainsList } from '../../redux/thunks/domains';
import { selectIsLoading } from '../../redux/selectors/loading';
import { selectUserDomains } from '../../redux/selectors/domains';
import RequestUtils from '../utils/RequestUtils';

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
        this.toggleDomains = this.toggleDomains.bind(this);
        this.showError = this.showError.bind(this);
        this.state = {
            errorMessage: '',
            showError: false,
            showDomains: !(props.hideDomains ? props.hideDomains : false),
        };
    }

    toggleDomains() {
        this.setState({
            showDomains: !this.state.showDomains,
        });
    }

    componentDidMount() {
        const { getDomainList } = this.props;
        Promise.all([getDomainList()]).catch((err) => {
            this.showError(RequestUtils.fetcherErrorCheckHelper(err));
        });
    }

    showError(errorMessage) {
        this.setState({
            showError: true,
            errorMessage: errorMessage,
        });
    }

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
                        <Link href={PageUtils.rolePage(domainName)} passHref legacyBehavior>
                            <StyledAnchor active={currentDomain === domainName}>
                                {domainName}
                            </StyledAnchor>
                        </Link>
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
                                <Link href={PageUtils.createDomainPage()} passHref legacyBehavior>
                                    <StyledAnchor>Create</StyledAnchor>
                                </Link>
                                <DividerSpan> | </DividerSpan>
                                <Link href={PageUtils.manageDomainPage()} passHref legacyBehavior>
                                    <StyledAnchor>Manage</StyledAnchor>
                                </Link>
                            </div>
                        </ManageDomainsHeaderDiv>
                        <DomainListDiv>
                            {this.state.showError
                                ? this.state.errorMessage
                                : userIcons}
                        </DomainListDiv>
                    </ShowDomainsDiv>
                )}
            </div>
        );
    }
}

const mapStateToProps = (state) => ({
    domains: selectUserDomains(state),
    isLoading: selectIsLoading(state),
});

const mapDispatchToProps = (dispatch) => ({
    getDomainList: () => dispatch(getUserDomainsList()),
});

export default connect(
    mapStateToProps,
    mapDispatchToProps
)(withRouter(UserDomains));
