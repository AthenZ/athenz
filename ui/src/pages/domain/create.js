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
import Header from '../../components/header/Header';
import UserDomains from '../../components/domain/UserDomains';
import API from '../../api';
import styled from '@emotion/styled';
import Head from 'next/head';

import RequestUtils from '../../components/utils/RequestUtils';
import Error from '../_error';
import createCache from '@emotion/cache';
import { CacheProvider } from '@emotion/react';
import JsonUtils from '../../components/utils/JsonUtils';
import CreateDomain from '../../components/domain/CreateDomain';

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

const CreateDomainContainerDiv = styled.div`
    align-items: stretch;
    flex: 1 1;
    height: calc(100vh - 60px);
    overflow: auto;
    display: flex;
    flex-direction: column;
`;

const CreateDomainContentDiv = styled.div``;

const PageHeaderDiv = styled.div`
    padding: 20px 30px 0;
`;

const TitleDiv = styled.div`
    font: 600 20px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
    margin-bottom: 10px;
`;

export async function getServerSideProps(context) {
    let api = API(context.req);
    let reload = false;
    let notFound = false;
    let error = null;
    const domains = await Promise.all([
        api.getHeaderDetails(),
        api.getForm(),
    ]).catch((err) => {
        let response = RequestUtils.errorCheckHelper(err);
        reload = response.reload;
        error = response.error;
        return [{}, {}, {}];
    });
    return {
        props: {
            reload,
            notFound,
            error,
            headerDetails: domains[0],
            domain: JsonUtils.omitUndefined(context.query.domain),
            _csrf: domains[1],
            nonce: context.req.headers.rid,
        },
    };
}

export default class CreateDomainPage extends React.Component {
    constructor(props) {
        super(props);
        this.api = API();
        this.cache = createCache({
            key: 'athenz',
            nonce: this.props.nonce,
        });
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
        return (
            <CacheProvider value={this.cache}>
                <div data-testid='create-domain'>
                    <Head>
                        <title>Athenz</title>
                    </Head>
                    <Header showSearch={false} />
                    <MainContentDiv>
                        <AppContainerDiv>
                            <CreateDomainContainerDiv>
                                <CreateDomainContentDiv>
                                    <PageHeaderDiv>
                                        <TitleDiv>Create New Domain</TitleDiv>
                                    </PageHeaderDiv>
                                    <CreateDomain
                                        userId={this.props.headerDetails.userId}
                                        _csrf={this.props._csrf}
                                        api={this.api}
                                        createDomainMessage={
                                            this.props.headerDetails
                                                .createDomainMessage
                                        }
                                    />
                                </CreateDomainContentDiv>
                            </CreateDomainContainerDiv>
                            <UserDomains />
                        </AppContainerDiv>
                    </MainContentDiv>
                </div>
            </CacheProvider>
        );
    }
}
