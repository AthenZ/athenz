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
import Head from 'next/head';
import { withRouter } from 'next/router';
import Header from '../../../components/header/Header';
import UserDomains from '../../../components/domain/UserDomains';
import styled from '@emotion/styled';
import { colors } from '../../../components/denali/styles';
import Icon from '../../../components/denali/icons/Icon';
import Error from '../../_error';
import Link from 'next/link';
import PageUtils from '../../../components/utils/PageUtils';
import {
    selectAllDomainsList,
    selectUserDomains,
} from '../../../redux/selectors/domains';
import {
    getAllDomainsList,
    getUserDomainsList,
} from '../../../redux/thunks/domains';
import { connect } from 'react-redux';
import createCache from '@emotion/cache';
import { CacheProvider } from '@emotion/react';
import RequestUtils from '../../../components/utils/RequestUtils';
import { searchServices } from '../../../redux/thunks/services';
import Menu from '../../../components/denali/Menu/Menu';
import { SEARCH_MAX_100_RESULTS_CAN_BE_DISPLAYED } from '../../../components/constants/constants';

const AppContainerDiv = styled.div`
    align-items: stretch;
    flex-flow: row nowrap;
    height: 100%;
    display: flex;
    justify-content: flex-start;
`;

const MainContentDiv = styled.div`
    flex: 1 1 calc(100vh - 60px);
    overflow: hidden;
    font: 300 14px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
`;

const SearchContainerDiv = styled.div`
    align-items: stretch;
    flex: 1 1;
    height: calc(100vh - 60px);
    overflow: auto;
    display: flex;
    flex-direction: column;
`;

const SearchContentDiv = styled.div``;

const PageHeaderDiv = styled.div`
    background: #f5f8fe;
    padding: 20px 30px 0;
`;

const TitleDiv = styled.div`
    font: 600 20px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
    margin-bottom: 10px;
    display: flex;
`;

const ResultsDiv = styled.div`
    color: #3570f4;
    margin-bottom: 5px;
    font: 100 14px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
    cursor: pointer;
    padding: 0 30px 10px;
    display: flex;
`;

const StyledAnchor = styled.a`
    color: #3570f4;
    text-decoration: none;
    cursor: pointer;
`;

const DomainLogoDiv = styled.div`
    font-size: 1.25em;
    margin-right: 5px;
    vertical-align: text-bottom;
`;

const ResultsCountDiv = styled.div`
    color: #9a9a9a;
`;

const LineSeparator = styled.div`
    border-bottom: 1px solid #d5d5d5;
    margin-top: 10px;
    margin-bottom: 10px;
    width: 100%;
`;

const MenuDiv = styled.div`
    padding: 5px 10px;
    background-color: black;
    color: white;
    font-size: 12px;
`;

export async function getServerSideProps(context) {
    let type = context.query.type;
    let reload = false;
    let error = null;
    return {
        props: {
            searchterm: context.query.searchterm,
            domainResults: [],
            type: type,
            error,
            reload,
            nonce: context.req && context.req.headers.rid,
            services: [],
        },
    };
}

function extractDomainAndService(domainService) {
    const lastDotIndex = domainService.lastIndexOf('.'); // Find the last occurrence of '.'

    if (lastDotIndex === -1) {
        // If no '.' is found, return nothing
        return ['', ''];
    }

    // Split the string into two parts: before and after the last '.'
    const domain = domainService.substring(0, lastDotIndex);
    const service = domainService.substring(lastDotIndex + 1);

    return [domain, service];
}

class PageSearchDetails extends React.Component {
    constructor(props) {
        super(props);
        this.cache = createCache({
            key: 'athenz',
            nonce: this.props.nonce,
        });
        this.state = {
            domainResults: props.domainResults,
            type: props.type,
            searchterm: props.searchterm,
            services: [],
            error: props.error,
        };
        this.findDomains = this.findDomains.bind(this);
        this.setupServicesSearchResults =
            this.setupServicesSearchResults.bind(this);
        this.performSearch = this.performSearch.bind(this);
        this.showError = this.showError.bind(this);
    }

    componentDidMount() {
        // on first load of the component
        this.performSearch();
    }

    showError(errorMessage) {
        this.setState({ error: errorMessage });
    }

    componentDidUpdate(prevProps, prevState, snapshot) {
        // if properties for this component change - e.g. on a new search - update state
        if (
            this.props.router.query.type !== prevProps.router.query.type ||
            this.props.router.query.searchterm !==
                prevProps.router.query.searchterm
        ) {
            this.setState(
                {
                    type: this.props.router.query.type,
                    searchterm: this.props.router.query.searchterm,
                },
                this.performSearch
            );
        }
    }

    performSearch() {
        // clear old search results before making new one
        // since domain search results are not stored in state
        // clear only services
        this.setState(
            {
                services: [],
            },
            () => {
                // perform search in callback
                switch (this.state.type) {
                    case 'domain':
                        {
                            if (!this.state.allDomainList) {
                                // searching for domains is done client-side
                                // so fetching domains can be done only once
                                Promise.all([
                                    this.props.getDomainList(),
                                    this.props.getAllDomainsList(),
                                ]).catch((err) => {
                                    this.showError(
                                        RequestUtils.fetcherErrorCheckHelper(
                                            err
                                        )
                                    );
                                });
                            }
                        }
                        break;
                    case 'service':
                        {
                            // searching for services is done server-side
                            // so each time search must be done anew
                            this.props
                                .searchServices(this.state.searchterm)
                                .then((data) => {
                                    this.setState({
                                        services: data ? data : [],
                                    });
                                })
                                .catch((err) => {
                                    this.showError(
                                        RequestUtils.fetcherErrorCheckHelper(
                                            err
                                        )
                                    );
                                });
                        }
                        break;
                }
            }
        );
    }

    findDomains(searchTerm) {
        const { allDomainList, userDomains } = this.props;
        let domainResults = [];
        if (allDomainList.length > 0 || userDomains.length > 0) {
            domainResults = allDomainList.filter((domain) => {
                return domain.name
                    .toLowerCase()
                    .includes(searchTerm.toLowerCase());
            });
            domainResults = domainResults.map((domain) => {
                let isUserDomain = false;
                let isAdminDomain = false;
                for (let userDomain of userDomains) {
                    if (userDomain.name === domain.name) {
                        isUserDomain = true;
                        if (userDomain.adminDomain) {
                            isAdminDomain = true;
                        }
                        break;
                    }
                }
                return {
                    name: domain.name,
                    userDomain: isUserDomain,
                    adminDomain: isAdminDomain,
                };
            });
        }
        return domainResults;
    }

    setupServicesSearchResults() {
        // setup services for display
        let items = [];
        this.state.services?.list?.forEach(function (service) {
            const [domain, serviceName] = extractDomainAndService(service.name);
            items.push(
                <ResultsDiv key={service.name} data-wdio={'search-result'}>
                    <Link
                        href={`${PageUtils.servicePage(
                            domain
                        )}/${serviceName}/instance/dynamic`}
                        passHref
                        legacyBehavior
                    >
                        <StyledAnchor>{service.name}</StyledAnchor>
                    </Link>
                </ResultsDiv>
            );
        });
        return (
            <SearchContainerDiv>
                <SearchContentDiv>
                    <PageHeaderDiv>
                        <TitleDiv>Search Results</TitleDiv>
                        <ResultsCountDiv>
                            {items.length} {`Service(s) `}
                            {this.state.services?.serviceMatchCount > 0 && (
                                <Menu
                                    placement='bottom-start'
                                    trigger={
                                        <span>
                                            <Icon
                                                icon={'help-circle'}
                                                isLink
                                                size={'15px'}
                                                color={colors.graphYellow}
                                                enableTitle={false}
                                            />
                                        </span>
                                    }
                                >
                                    <MenuDiv>
                                        {
                                            SEARCH_MAX_100_RESULTS_CAN_BE_DISPLAYED
                                        }
                                    </MenuDiv>
                                </Menu>
                            )}
                        </ResultsCountDiv>
                        <LineSeparator />
                    </PageHeaderDiv>
                    {items}
                </SearchContentDiv>
            </SearchContainerDiv>
        );
    }

    setupDomainSearchResults(domainResults) {
        // setup domains for display
        let items = [];
        domainResults.forEach(function (currentDomain) {
            let domain = currentDomain.name;
            let showIcon =
                currentDomain.adminDomain || currentDomain.userDomain;
            let iconType = currentDomain.adminDomain
                ? 'user-secure'
                : 'user-group';
            let icon;
            if (showIcon) {
                icon = (
                    <Icon
                        icon={iconType}
                        color={colors.black}
                        isLink
                        size={'1em'}
                        verticalAlign={'text-bottom'}
                    />
                );
            }
            items.push(
                <ResultsDiv key={domain} data-wdio={'search-result'}>
                    <DomainLogoDiv>{icon}</DomainLogoDiv>
                    <Link
                        href={PageUtils.rolePage(domain)}
                        passHref
                        legacyBehavior
                    >
                        <StyledAnchor>{domain}</StyledAnchor>
                    </Link>
                </ResultsDiv>
            );
        });
        return (
            <SearchContainerDiv>
                <SearchContentDiv>
                    <PageHeaderDiv>
                        <TitleDiv>Search Results</TitleDiv>
                        <ResultsCountDiv>
                            {items.length} Domain(s)
                        </ResultsCountDiv>
                        <LineSeparator />
                    </PageHeaderDiv>
                    {items}
                </SearchContentDiv>
            </SearchContainerDiv>
        );
    }

    render() {
        const { reload } = this.props;
        if (reload) {
            window.location.reload();
            return <div />;
        }
        if (this.state.error) {
            return <Error err={this.state.error} />;
        }

        let resultsToDisplay = '';
        // prepare results for display depending on search type
        if (this.state.type === 'domain') {
            let domainResult = this.findDomains(
                this.props.router.query.searchterm
            );
            resultsToDisplay = this.setupDomainSearchResults(domainResult);
        } else if (this.state.type === 'service') {
            resultsToDisplay = this.setupServicesSearchResults();
        }
        return (
            <CacheProvider value={this.cache}>
                <div data-testid='search'>
                    <Head>
                        <title>{this.state.searchterm} - Athenz</title>
                    </Head>
                    <Header
                        showSearch={true}
                        searchData={this.props.searchterm}
                    />
                    <MainContentDiv>
                        <AppContainerDiv>
                            {resultsToDisplay}
                            <UserDomains />
                        </AppContainerDiv>
                    </MainContentDiv>
                </div>
            </CacheProvider>
        );
    }
}

const mapStateToProps = (state, props) => {
    return {
        ...props,
        allDomainList: selectAllDomainsList(state),
        userDomains: selectUserDomains(state),
    };
};

const mapDispatchToProps = (dispatch) => ({
    getAllDomainsList: () => dispatch(getAllDomainsList()),
    getDomainList: () => dispatch(getUserDomainsList()),
    searchServices: (subString) => dispatch(searchServices(subString)),
});

export default connect(
    mapStateToProps,
    mapDispatchToProps
)(withRouter(PageSearchDetails));
