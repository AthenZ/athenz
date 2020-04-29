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
import Head from 'next/head';
import { withRouter } from 'next/router';
import { Link } from '../routes';
import API from '../api';
import Header from '../components/header/Header';
import UserDomains from '../components/domain/UserDomains';
import styled from '@emotion/styled';
// there is an issue with next-link and next-css if the css is not present then it doesnt load so adding this
import 'flatpickr/dist/themes/light.css';
import { colors } from '../components/denali/styles';
import Icon from '../components/denali/icons/Icon';
import RequestUtils from '../components/utils/RequestUtils';
import Error from './_error';

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

class PageSearchDetails extends React.Component {
    static async getInitialProps(props) {
        let api = API(props.req);
        let promises = [];
        promises.push(api.listUserDomains());
        let type = props.query.type;
        let reload = false;
        let error = null;
        if (type === 'domain') {
            promises.push(api.searchDomains(props.query.searchterm));
        }
        promises.push(api.getHeaderDetails());
        const values = await Promise.all(promises).catch((err) => {
            let response = RequestUtils.errorCheckHelper(err);
            reload = response.reload;
            error = response.error;
            return [{}, {}, {}];
        });
        let domainResults = [];
        if (type === 'domain') {
            domainResults = values[1];
        }
        return {
            api,
            domain: props.query.searchterm,
            domains: values[0],
            domainResults,
            type: type,
            headerDetails: values[2],
            error,
            reload,
        };
    }

    constructor(props) {
        super(props);
        this.api = props.api || API();
        this.state = {
            domains: props.domains,
            domainResults: props.domainResults,
            type: props.type,
            domain: props.domain,
        };
    }

    componentDidUpdate = (prevProps) => {
        if (
            this.props.router.query.searchterm !==
                prevProps.router.query.searchterm ||
            this.props.router.query.type !== prevProps.router.query.type
        ) {
            let promises = [];
            promises.push(this.api.listUserDomains());
            let type = this.props.router.query.type;
            if (type === 'domain') {
                promises.push(
                    this.api.searchDomains(this.props.router.query.searchterm)
                );
            }
            Promise.all(promises)
                .then((values) => {
                    let domainResults = [];
                    if (type === 'domain') {
                        domainResults = values[1];
                        this.setState({
                            domainResults: domainResults,
                            type: type,
                        });
                    }
                })
                .catch((err) => {});
        }
    };

    displayDomainResults() {
        let items = [];
        this.state.domainResults.forEach(function(currentDomain) {
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
                <ResultsDiv key={domain}>
                    <DomainLogoDiv>{icon}</DomainLogoDiv>
                    <Link route='role' params={{ domain }}>
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
                            {this.state.domainResults.length} Results
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
        if (this.props.error) {
            return <Error err={this.props.error} />;
        }
        let displayDomainResults = '';
        if (this.state.type === 'domain') {
            displayDomainResults = this.displayDomainResults();
        }
        return (
            <div data-testid='search'>
                <Head>
                    <title>{this.state.domain} - Athenz</title>
                </Head>
                <Header
                    showSearch={true}
                    headerDetails={this.props.headerDetails}
                    searchData={this.props.domain}
                />
                <MainContentDiv>
                    <AppContainerDiv>
                        {displayDomainResults}
                        <UserDomains
                            domains={this.state.domains}
                            api={this.api}
                        />
                    </AppContainerDiv>
                </MainContentDiv>
            </div>
        );
    }
}

export default withRouter(PageSearchDetails);
