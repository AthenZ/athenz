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
import Header from '../components/header/Header';
import UserDomains from '../components/domain/UserDomains';
import API from '../api.js';
import styled from '@emotion/styled';
import Head from 'next/head';

import Search from '../components/search/Search';
import RequestUtils from '../components/utils/RequestUtils';
import Error from './_error';
import createCache from '@emotion/cache';
import { CacheProvider } from '@emotion/react';

const HomeContainerDiv = styled.div`
    flex: 1 1;
`;

const HomeContentDiv = styled.div`
    align-items: center;
    height: 100%;
    justify-content: flex-start;
    width: 100%;
    display: flex;
    flex-direction: column;
`;

const Logo = ({ className }) => (
    <img src='/static/athenz-logo.png' className={className} />
);

const LogoStyled = styled(Logo)`
    height: 100px;
    width: 100px;
`;

const MainLogoDiv = styled.div`
    padding-top: 20px;
`;

const DetailsDiv = styled.div`
    align-items: flex-start;
    line-height: 1.3;
    padding: 20px 0;
    text-align: center;
    width: 650px;
`;

const SearchContainerDiv = styled.div`
    padding: 20px 0 0 0;
    width: 600px;
`;

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

const StyledAnchor = styled.a`
    color: #3570f4;
    text-decoration: none;
    cursor: pointer;
`;

export default class PageHome extends React.Component {
    static async getInitialProps({ req }) {
        let api = API(req);
        let reload = false;
        let error = null;
        const domains = await Promise.all([
            api.listUserDomains(),
            api.getHeaderDetails(),
            api.getPendingDomainMembersList(),
        ]).catch((err) => {
            let response = RequestUtils.errorCheckHelper(err);
            reload = response.reload;
            error = response.error;
            return [{}, {}, {}];
        });
        return {
            api,
            reload,
            error,
            domains: domains[0],
            headerDetails: domains[1],
            pending: domains[2],
            nonce: req.headers.rid,
        };
    }

    constructor(props) {
        super(props);
        this.api = props.api || API();
        this.cache = createCache({
            key: 'athenz',
            nonce: this.props.nonce,
        });
    }

    render() {
        if (this.props.reload) {
            window.location.reload();
            return <div />;
        }
        if (this.props.error) {
            return <Error err={this.props.error} />;
        }
        return (
            <CacheProvider value={this.cache}>
                <div data-testid='home'>
                    <Head>
                        <title>Athenz</title>
                    </Head>
                    <Header
                        showSearch={false}
                        headerDetails={this.props.headerDetails}
                        pending={this.props.pending}
                    />
                    <MainContentDiv>
                        <AppContainerDiv>
                            <HomeContainerDiv>
                                <HomeContentDiv>
                                    <MainLogoDiv>
                                        <LogoStyled />
                                    </MainLogoDiv>
                                    <DetailsDiv>
                                        <span>
                                            Athenz is an open source platform
                                            which provides secure identity in
                                            the form of X.509 certificate to
                                            every workload for service
                                            authentication (mutual TLS
                                            authentication) and provides
                                            fine-grained Role Based Access
                                            Control (RBAC) for authorization.
                                        </span>
                                        <StyledAnchor
                                            rel='noopener'
                                            target='_blank'
                                            href='https://git.ouroath.com/pages/athens/athenz-guide/'
                                        >
                                            Learn more
                                        </StyledAnchor>
                                    </DetailsDiv>
                                    <SearchContainerDiv>
                                        <Search />
                                    </SearchContainerDiv>
                                </HomeContentDiv>
                            </HomeContainerDiv>
                            <UserDomains
                                domains={this.props.domains}
                                api={this.api}
                            />
                        </AppContainerDiv>
                    </MainContentDiv>
                </div>
            </CacheProvider>
        );
    }
}
