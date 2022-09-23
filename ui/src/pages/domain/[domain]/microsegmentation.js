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
import Error from '../../_error';
import DomainDetails from '../../../components/header/DomainDetails';
import Tabs from '../../../components/header/Tabs';
import DomainNameHeader from '../../../components/header/DomainNameHeader';
import { selectIsLoading } from '../../../redux/selectors/loading';
import { selectDomainData } from '../../../redux/selectors/domainData';
import { getDomainData } from '../../../redux/thunks/domain';
import { connect } from 'react-redux';
import { getInboundOutbound } from '../../../redux/thunks/microsegmentation';
import RulesList from '../../../components/microsegmentation/RulesList';
import Alert from '../../../components/denali/Alert';
import { CacheProvider } from '@emotion/react';
import createCache from '@emotion/cache';
import { ReduxPageLoader } from '../../../components/denali/ReduxPageLoader';

const AppContainerDiv = styled.div`
    align-items: stretch;
    flex-flow: row nowrap;
    height: 100%;
    display: flex;
    justify-content: flex-start;
`;

const TitleDiv = styled.div`
    font: 600 20px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
    margin-bottom: 10px;
`;

const MainContentDiv = styled.div`
    flex: 1 1 calc(100vh - 60px);
    overflow: hidden;
    font: 300 14px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
`;

const RolesContainerDiv = styled.div`
    align-items: stretch;
    flex: 1 1;
    height: calc(100vh - 60px);
    overflow: auto;
    display: flex;
    flex-direction: column;
`;

const RolesContentDiv = styled.div``;

const PageHeaderDiv = styled.div`
    background: linear-gradient(to top, #f2f2f2, #fff);
    padding: 20px 30px 0;
`;

export async function getServerSideProps(context) {
    let api = API(context.req);
    let reload = false;
    let notFound = false;
    let error = null;

    const data = await Promise.all([
        api.getForm(),
        api.getPageFeatureFlag('microsegmentation'),
    ]).catch((err) => {
        let response = RequestUtils.errorCheckHelper(err);
        reload = response.reload;
        error = response.error;
        return [{}, {}];
    });

    return {
        props: {
            reload,
            notFound,
            error,
            userName: context.req.session.shortId,
            domain: context.query.domain,
            _csrf: data[0],
            nonce: context.req.headers.rid,
            featureFlag: true,
            pageFeatureFlag: data[1],
        },
    };
}

export class MicrosegmentationPage extends React.Component {
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
        const { domain, getDomainData, userName, getInboundOutbound } =
            this.props;
        Promise.all([
            getDomainData(domain, userName),
            getInboundOutbound(domain),
        ]).catch((err) => {
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
        const { domain, reload, _csrf, isLoading, domainData } = this.props;
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
                <div data-testid='microsegmentation'>
                    <Head>
                        <title>Athenz</title>
                    </Head>
                    <Header showSearch={true} />
                    <MainContentDiv>
                        <AppContainerDiv>
                            <RolesContainerDiv>
                                <RolesContentDiv>
                                    <PageHeaderDiv>
                                        <DomainNameHeader domainName={domain} />
                                        <DomainDetails
                                            api={this.api}
                                            _csrf={_csrf}
                                        />
                                        <Tabs
                                            domain={domain}
                                            selectedName={'microsegmentation'}
                                        />
                                    </PageHeaderDiv>
                                    <RulesList
                                        api={this.api}
                                        domain={domain}
                                        _csrf={_csrf}
                                        pageFeatureFlag={
                                            this.props.pageFeatureFlag
                                        }
                                    />
                                </RolesContentDiv>
                            </RolesContainerDiv>
                            <UserDomains domain={domain} />
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
    getInboundOutbound: (domainName) =>
        dispatch(getInboundOutbound(domainName)),
});

export default connect(
    mapStateToProps,
    mapDispatchToProps
)(MicrosegmentationPage);
