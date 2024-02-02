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
import Header from '../components/header/Header';
import styled from '@emotion/styled';
import Head from 'next/head';

import Color from '../components/denali/Color';
import { CacheProvider } from '@emotion/react';
import createCache from '@emotion/cache';
import { withRouter } from 'next/router';
import Link from 'next/link';
import PageUtils from '../components/utils/PageUtils';

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

const DetailsDiv = styled.div`
    align-items: flex-start;
    line-height: 1.3;
    padding: 20px 0;
    text-align: center;
    width: 650px;
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

const HomeDiv = styled.div`
    margin-top: 20px;
`;

class Error extends React.Component {
    static async getInitialProps({ res, err }) {
        const statusCode = res ? res.statusCode : err ? err.statusCode : 404;
        return {
            statusCode,
            err,
        };
    }

    constructor(props) {
        super(props);
        this.cache = createCache({
            key: 'athenz',
            nonce: this.props.nonce,
        });
    }

    render() {
        let errorMsg = '';
        if (this.props.err) {
            if (this.props.err.message) {
                errorMsg = this.props.err.message;
            } else if (typeof this.props.err === 'string') {
                errorMsg = this.props.err;
            }
        }
        if (this.props.statusCode === 404) {
            errorMsg = 'I sense a disturbance in the Force!';
        }

        return (
            <CacheProvider value={this.cache}>
                <div data-testid='error'>
                    <Head>
                        <title>Athenz</title>
                    </Head>
                    <Header showSearch={false} userId={''} pending={[]} />
                    <MainContentDiv>
                        <AppContainerDiv>
                            <HomeContainerDiv>
                                <HomeContentDiv>
                                    <DetailsDiv>
                                        <span>
                                            <Color name={'red600'}>
                                                {errorMsg}
                                            </Color>
                                        </span>
                                        <HomeDiv>
                                            <Link href={PageUtils.homePage()}>
                                                Athenz Home
                                            </Link>
                                        </HomeDiv>
                                    </DetailsDiv>
                                </HomeContentDiv>
                            </HomeContainerDiv>
                        </AppContainerDiv>
                    </MainContentDiv>
                </div>
            </CacheProvider>
        );
    }
}

export default withRouter(Error);
