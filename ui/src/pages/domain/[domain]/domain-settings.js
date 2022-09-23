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
import Header from '../../../components/header/Header';
import UserDomains from '../../../components/domain/UserDomains';
import API from '../../../api';
import styled from '@emotion/styled';
import Head from 'next/head';
import RequestUtils from '../../../components/utils/RequestUtils';
import Tabs from '../../../components/header/Tabs';
import Error from '../../_error';
import DomainNameHeader from '../../../components/header/DomainNameHeader';
import { getDomainData } from '../../../redux/thunks/domain';
import { connect } from 'react-redux';
import SettingTable from '../../../components/settings/SettingTable';
import { selectDomainData } from '../../../redux/selectors/domainData';
import { selectIsLoading } from '../../../redux/selectors/loading';
import DomainDetails from '../../../components/header/DomainDetails';
import Alert from '../../../components/denali/Alert';
import createCache from '@emotion/cache';
import { CacheProvider } from '@emotion/react';
import { ReduxPageLoader } from '../../../components/denali/ReduxPageLoader';

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

const DomainSettingsContainerDiv = styled.div`
    align-items: stretch;
    flex: 1 1;
    height: calc(100vh - 60px);
    overflow: auto;
    display: flex;
    flex-direction: column;
`;

const DomainSettingsContentDiv = styled.div``;

const PageHeaderDiv = styled.div`
    background: linear-gradient(to top, #f2f2f2, #fff);
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
    const domains = await Promise.all([api.getForm()]).catch((err) => {
        let response = RequestUtils.errorCheckHelper(err);
        reload = response.reload;
        error = response.error;
        return [{}];
    });
    return {
        props: {
            reload,
            notFound,
            error,
            domainName: context.query.domain,
            userName: context.req.session.shortId,
            _csrf: domains[0],
            nonce: context.req.headers.rid,
        },
    };
}

class DomainSettingsPage extends React.Component {
    constructor(props) {
        super(props);
        this.api = API();
        this.cache = createCache({
            key: 'athenz',
            nonce: this.props.nonce,
        });
        this.state = {
            errorMessage: '',
            showError: false,
        };
        this.showError = this.showError.bind(this);
    }

    componentDidMount() {
        const { getDomainData, domainName, userName } = this.props;
        Promise.all([getDomainData(domainName, userName)]).catch((err) => {
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
        const { domainName, domainData, reload, isLoading, _csrf } = this.props;
        if (reload) {
            window.location.reload();
            return <div />;
        }
        if (this.props.error) {
            return <Error err={this.props.error} />;
        }

        if (this.state.showError) {
            return (
                <Alert
                    isOpen={this.state.showError}
                    title={this.state.errorMessage}
                    onClose={() => {}}
                    type='danger'
                />
            );
        }

        return isLoading.includes('getDomainData') ? (
            <ReduxPageLoader message={'Loading domain data'} />
        ) : (
            <CacheProvider value={this.cache}>
                <div data-testid='domain-settings'>
                    <Head>
                        <title>Athenz</title>
                    </Head>
                    <Header showSearch={true} />
                    <MainContentDiv>
                        <AppContainerDiv>
                            <DomainSettingsContainerDiv>
                                <DomainSettingsContentDiv>
                                    <PageHeaderDiv>
                                        <DomainNameHeader
                                            showSearch={true}
                                            domainName={domainName}
                                        />
                                        <DomainDetails
                                            api={this.api}
                                            _csrf={_csrf}
                                        />
                                        <Tabs
                                            domain={domainName}
                                            selectedName={'domain-settings'}
                                        />
                                    </PageHeaderDiv>
                                    <SettingTable
                                        domain={domainName}
                                        collection={domainName}
                                        collectionDetails={domainData}
                                        _csrf={_csrf}
                                        category={'domain'}
                                    />
                                </DomainSettingsContentDiv>
                            </DomainSettingsContainerDiv>
                            <UserDomains domain={domainName} />
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
        isLoading: selectIsLoading(state),
        domainData: selectDomainData(state),
    };
};

const mapDispatchToProps = (dispatch) => ({
    getDomainData: (domainName, userName) =>
        dispatch(getDomainData(domainName, userName)),
});

export default connect(mapStateToProps, mapDispatchToProps)(DomainSettingsPage);
