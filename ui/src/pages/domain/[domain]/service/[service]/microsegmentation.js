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
import Header from '../../../../../components/header/Header';
import UserDomains from '../../../../../components/domain/UserDomains';
import API from '../../../../../api';
import styled from '@emotion/styled';
import Head from 'next/head';
import RequestUtils from '../../../../../components/utils/RequestUtils';
import Error from '../../../../_error';
import NameHeader from '../../../../../components/header/NameHeader';
import CollectionDetails from '../../../../../components/header/CollectionDetails';
import { getDomainData } from '../../../../../redux/thunks/domain';
import { connect } from 'react-redux';
import { selectIsLoading } from '../../../../../redux/selectors/loading';
import createCache from '@emotion/cache';
import { CacheProvider } from '@emotion/react';
import { ReduxPageLoader } from '../../../../../components/denali/ReduxPageLoader';
import { selectService } from '../../../../../redux/selectors/services';
import ServiceTabs from '../../../../../components/header/ServiceTabs';
import { getInboundOutbound } from '../../../../../redux/thunks/microsegmentation';
import RulesList from '../../../../../components/microsegmentation/RulesList';
import Alert from '../../../../../components/denali/Alert';
import { selectFeatureFlag } from '../../../../../redux/selectors/domains';

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

const MicrosegmentationContainerDiv = styled.div`
    align-items: stretch;
    flex: 1 1;
    height: calc(100vh - 60px);
    overflow: auto;
    display: flex;
    flex-direction: column;
`;

const MicrosegmentationContentDiv = styled.div``;

const PageHeaderDiv = styled.div`
    background: linear-gradient(to top, #f2f2f2, #fff);
    padding: 20px 30px 0;
`;

export async function getServerSideProps(context) {
    let api = API(context.req);
    let reload = false;
    let notFound = false;
    let error = null;
    const microsegmentationData = await Promise.all([
        api.getForm(),
        api.getPageFeatureFlag('microsegmentation'),
    ]).catch((err) => {
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
            serviceName: context.query.service,
            userName: context.req.session.shortId,
            _csrf: microsegmentationData[0],
            domainName: context.query.domain,
            nonce: context.req.headers.rid,
            pageFeatureFlag: microsegmentationData[1],
        },
    };
}

class ServiceMicrosegmentationPage extends React.Component {
    constructor(props) {
        super(props);
        this.api = API();
        this.cache = createCache({
            key: 'athenz',
            nonce: this.props.nonce,
        });
        this.state = {
            error: null,
            reload: false,
            errorMessage: '',
            showError: false,
        };
    }

    componentDidMount() {
        const { domainName, userName, getDomainData, getInboundOutbound } =
            this.props;
        Promise.all([
            getDomainData(domainName, userName),
            getInboundOutbound(domainName),
        ]).catch((err) => {
            let response = RequestUtils.errorCheckHelper(err);
            this.setState({
                error: response.error,
                reload: response.reload,
            });
        });
    }

    showError(errorMessage) {
        this.setState({
            showError: true,
            errorMessage: errorMessage,
        });
    }

    render() {
        const {
            domainName,
            reload,
            serviceName,
            serviceDetails,
            _csrf,
            isLoading,
        } = this.props;
        if (reload || this.state.reload) {
            window.location.reload();
            return <div />;
        }
        const err = this.props.error || this.state.error;
        if (err) {
            return <Error err={err} />;
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
                <div data-testid='service-microsegmentation'>
                    <Head>
                        <title>Athenz Service Microsegmentation</title>
                    </Head>
                    <Header showSearch={true} />
                    <MainContentDiv>
                        <AppContainerDiv>
                            <MicrosegmentationContainerDiv>
                                <MicrosegmentationContentDiv>
                                    <PageHeaderDiv>
                                        <NameHeader
                                            category={'service'}
                                            domain={domainName}
                                            collection={serviceName}
                                            collectionDetails={
                                                serviceDetails || {}
                                            }
                                        />
                                        <CollectionDetails
                                            categroy={'service'}
                                            collectionDetails={
                                                serviceDetails || {}
                                            }
                                            _csrf={_csrf}
                                        />
                                        <ServiceTabs
                                            featureFlag={this.props.featureFlag}
                                            domain={domainName}
                                            service={serviceName}
                                            selectedName={'microsegmentation'}
                                        />
                                    </PageHeaderDiv>
                                    <RulesList
                                        api={this.api}
                                        domain={domainName}
                                        filterByService={serviceName}
                                        _csrf={_csrf}
                                        pageFeatureFlag={
                                            this.props.pageFeatureFlag
                                        }
                                    />
                                </MicrosegmentationContentDiv>
                            </MicrosegmentationContainerDiv>
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
        featureFlag: selectFeatureFlag(state),
        serviceDetails: selectService(
            state,
            props.domainName,
            props.serviceName
        ),
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
)(ServiceMicrosegmentationPage);
