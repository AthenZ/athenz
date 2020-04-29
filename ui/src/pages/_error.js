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
import styled from '@emotion/styled';
import Head from 'next/head';
// there is an issue with next-link and next-css if the css is not present then it doesnt load so adding this
import 'flatpickr/dist/themes/light.css';
import Color from '../components/denali/Color';
import { Link } from '../routes';
import NavBarItem from '../components/denali/NavBarItem';

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

export default class Error extends React.Component {
    static async getInitialProps({ res, err }) {
        const statusCode = res ? res.statusCode : err ? err.statusCode : 404;
        return { statusCode, err };
    }

    render() {
        let errorMsg = '';
        if (this.props.err) {
            if (this.props.err.message) {
                errorMsg = this.props.err.message;
            }
        }
        if (this.props.statusCode === 404) {
            errorMsg = 'I sense a disturbance in the Force!';
        }

        return (
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
                                        <Link route='home'>
                                            <a>Athenz Home</a>
                                        </Link>
                                    </HomeDiv>
                                </DetailsDiv>
                            </HomeContentDiv>
                        </HomeContainerDiv>
                    </AppContainerDiv>
                </MainContentDiv>
            </div>
        );
    }
}
