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
import Header from '../../../../../../components/header/Header';
import UserDomains from '../../../../../../components/domain/UserDomains';
import API from '../../../../../../api';
import styled from '@emotion/styled';
import Head from 'next/head';

import RequestUtils from '../../../../../../components/utils/RequestUtils';
import Error from '../../../../../_error';
import ServiceTabs from '../../../../../../components/header/ServiceTabs';
import ServiceNameHeader from '../../../../../../components/header/ServiceNameHeader';
import ServiceInstanceDetails from '../../../../../../components/header/ServiceInstanceDetails';
import {
    MODAL_TIME_OUT,
    SERVICE_TYPE_STATIC,
} from '../../../../../../components/constants/constants';
import { connect } from 'react-redux';
import {
    selectInstancesWorkLoadMeta,
    selectStaticServiceHeaderDetails,
} from '../../../../../../redux/selectors/services';
import { selectFeatureFlag } from '../../../../../../redux/selectors/domains';
import { getServiceHeaderAndInstances } from '../../../../../../redux/thunks/services';
import InstanceList from '../../../../../../components/service/InstanceList';
import { selectIsLoading } from '../../../../../../redux/selectors/loading';
import createCache from '@emotion/cache';
import { CacheProvider } from '@emotion/react';
import { ReduxPageLoader } from '../../../../../../components/denali/ReduxPageLoader';
import Alert from '../../../../../../components/denali/Alert';

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

const ServiceContainerDiv = styled.div`
    align-items: stretch;
    flex: 1 1;
    height: calc(100vh - 60px);
    overflow: auto;
    display: flex;
    flex-direction: column;
`;

const ServiceContentDiv = styled.div``;

const PageHeaderDiv = styled.div`
    background: linear-gradient(to top, #f2f2f2, #fff);
    padding: 20px 30px 0;
`;

export async function getServerSideProps(context) {
    let api = API(context.req);
    let reload = false;
    let notFound = false;
    let error = null;
    const data = await Promise.all([api.getForm()]).catch((err) => {
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
            domainName: context.query.domain,
            _csrf: data[0],
            nonce: context.req.headers.rid,
        },
    };
}

class StaticInstancePage extends React.Component {
    constructor(props) {
        super(props);
        this.onInstancesUpdated = this.onInstancesUpdated.bind(this);
        this.closeModal = this.closeModal.bind(this);
        this.cache = createCache({
            key: 'athenz',
            nonce: this.props.nonce,
        });
        this.state = {
            error: null,
            reload: false,
            showSuccess: false,
            successMessage: '',
        };
    }

    componentDidMount() {
        const { domainName, serviceName } = this.props;
        Promise.all([
            this.props.getServiceHeaderAndInstances(
                domainName,
                serviceName,
                SERVICE_TYPE_STATIC
            ),
        ]).catch((err) => {
            let response = RequestUtils.errorCheckHelper(err);
            this.setState({
                error: response.error,
                reload: response.reload,
            });
        });
    }

    onInstancesUpdated(successMessage, showSuccess = true) {
        this.setState({
            showSuccess: showSuccess,
            successMessage: successMessage,
        });
        setTimeout(
            () =>
                this.setState({
                    showSuccess: false,
                    successMessage: '',
                }),
            MODAL_TIME_OUT
        );
    }

    closeModal() {
        this.setState({ showSuccess: null });
    }

    render() {
        const {
            domainName,
            reload,
            serviceName,
            _csrf,
            instanceWorkLoadMeta,
            serviceHeaderDetails,
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

        return isLoading.includes('getDomainData') ? (
            <ReduxPageLoader message={'Loading domain data'} />
        ) : (
            <CacheProvider value={this.cache}>
                <div data-testid='static-instance'>
                    <Head>
                        <title>Athenz</title>
                    </Head>
                    <Header showSearch={true} domainName={domainName} />
                    <MainContentDiv>
                        <AppContainerDiv>
                            <ServiceContainerDiv>
                                <ServiceContentDiv>
                                    <PageHeaderDiv>
                                        <ServiceNameHeader
                                            domain={domainName}
                                            service={serviceName}
                                            serviceHeaderDetails={
                                                serviceHeaderDetails
                                            }
                                        />
                                        <ServiceInstanceDetails
                                            instanceDetailsMeta={
                                                instanceWorkLoadMeta
                                            }
                                            categoryType={SERVICE_TYPE_STATIC}
                                        />
                                        <ServiceTabs
                                            featureFlag={this.props.featureFlag}
                                            domain={domainName}
                                            service={serviceName}
                                            selectedName={SERVICE_TYPE_STATIC}
                                        />
                                    </PageHeaderDiv>
                                    <InstanceList
                                        category={SERVICE_TYPE_STATIC}
                                        domain={domainName}
                                        _csrf={_csrf}
                                        showSuccess={this.state.showSuccess}
                                        successMessage={
                                            this.state.successMessage
                                        }
                                        onInstancesUpdated={
                                            this.onInstancesUpdated
                                        }
                                        service={serviceName}
                                    />
                                    {this.state.showSuccess ? (
                                        <Alert
                                            isOpen={this.state.showSuccess}
                                            title={this.state.successMessage}
                                            onClose={this.closeModal}
                                            type='success'
                                        />
                                    ) : null}
                                </ServiceContentDiv>
                            </ServiceContainerDiv>
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
        instanceWorkLoadMeta: selectInstancesWorkLoadMeta(
            state,
            props.domainName,
            props.serviceName,
            SERVICE_TYPE_STATIC
        ),
        serviceHeaderDetails: selectStaticServiceHeaderDetails(
            state,
            props.domain,
            props.service
        ),
        isLoading: selectIsLoading(state),
        featureFlag: selectFeatureFlag(state),
    };
};

const mapDispatchToProps = (dispatch) => ({
    getServiceHeaderAndInstances: (domainName, serviceName, category) =>
        dispatch(
            getServiceHeaderAndInstances(domainName, serviceName, category)
        ),
});

export default connect(mapStateToProps, mapDispatchToProps)(StaticInstancePage);
