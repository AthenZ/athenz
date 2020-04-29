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
import Head from 'next/head';
// there is an issue with next-link and next-css if the css is not present then it doesnt load so adding this
import 'flatpickr/dist/themes/light.css';
import NavBar from '../components/denali/NavBar';
import NavBarItem from '../components/denali/NavBarItem';
import { Link, Router } from '../routes';
import InputLabel from '../components/denali/InputLabel';
import Input from '../components/denali/Input';
import Button from '../components/denali/Button';
import API from '../api';

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

const MainLogoDiv = styled.div`
    padding-top: 20px;
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

const Logo = ({ className }) => (
    <img src='/static/athenz-logo-full.png' className={className} />
);

const LogoStyled = styled(Logo)`
    height: 36px;
    cursor: pointer;
`;

const NavBarDiv = styled.div`
    height: 60px;
    position: relative;
`;

const SectionDiv = styled.div`
    align-items: flex-start;
    display: flex;
    flex-flow: row nowrap;
    padding: 10px 10px;
`;

const StyledInputLabel = styled(InputLabel)`
    float: left;
    font-size: 14px;
    font-weight: 700;
    padding-top: 12px;
    width: 25%;
`;

const ContentDiv = styled.div`
    flex: 1 1;
    margin: 10px;
`;

const StyledInput = styled(Input)`
    width: 500px;
`;

const ModifiedButton = styled(Button)`
    min-width: 8.5em;
    min-height: 1em;
`;

const ButtonDiv = styled.div`
    text-align: center;
`;

export default class PageLogin extends React.Component {
    static async getInitialProps(props) {
        let api = API(props.req);
        let options = '';
        let error = '';

        await api
            .getAuthOptions()
            .then((data) => {
                options = data;
            })
            .catch((err) => {
                error = err;
            });

        return {
            options,
            error,
        };
    }

    constructor(props) {
        super(props);
        this.state = {
            username: '',
            password: '',
        };
        this.onSubmit = this.onSubmit.bind(this);
    }

    inputChanged(key, evt) {
        this.setState({ [key]: evt.target.value });
    }

    onSubmit() {
        let cred = Buffer.from(
            this.state.username + ':' + this.state.password
        ).toString('base64');
        fetch(
            `${this.props.options.zms}user/_self_/token?services=${this.props.options.athenzDomainService}`,
            {
                headers: {
                    Authorization: 'Basic ' + cred,
                },
            }
        )
            .then((response) => {
                return response.json();
            })
            .then(
                (result) => {
                    if (result.token) {
                        fetch(`/login`, {
                            headers: {
                                token: result.token,
                            },
                        }).then((response) => {
                            if (response && response.status === 200) {
                                Router.pushRoute('home', {});
                            }
                        });
                    }
                },
                (error) => {
                    this.setState({
                        error,
                    });
                }
            );
    }

    render() {
        return (
            <div data-testid='home'>
                <Head>
                    <title>Athenz</title>
                </Head>
                <NavBarDiv data-testid='header'>
                    <NavBar background={'#002339'}>
                        <NavBarItem>
                            <Link route='home'>
                                <a>
                                    <LogoStyled />
                                </a>
                            </Link>
                        </NavBarItem>
                    </NavBar>
                </NavBarDiv>
                <MainContentDiv>
                    <AppContainerDiv>
                        <HomeContainerDiv>
                            <HomeContentDiv>
                                <MainLogoDiv>
                                    <SectionDiv>
                                        <StyledInputLabel>
                                            Username
                                        </StyledInputLabel>
                                        <ContentDiv>
                                            <StyledInput
                                                placeholder='Enter Username'
                                                value={this.state.username}
                                                onChange={this.inputChanged.bind(
                                                    this,
                                                    'username'
                                                )}
                                                noanim
                                                fluid
                                            />
                                        </ContentDiv>
                                    </SectionDiv>
                                    <SectionDiv>
                                        <StyledInputLabel>
                                            Password
                                        </StyledInputLabel>
                                        <ContentDiv>
                                            <StyledInput
                                                placeholder='Enter Password'
                                                value={this.state.password}
                                                onChange={this.inputChanged.bind(
                                                    this,
                                                    'password'
                                                )}
                                                noanim
                                                fluid
                                                type='password'
                                            />
                                        </ContentDiv>
                                    </SectionDiv>
                                    <ButtonDiv>
                                        <ModifiedButton onClick={this.onSubmit}>
                                            Login
                                        </ModifiedButton>
                                    </ButtonDiv>
                                </MainLogoDiv>
                            </HomeContentDiv>
                        </HomeContainerDiv>
                    </AppContainerDiv>
                </MainContentDiv>
            </div>
        );
    }
}
