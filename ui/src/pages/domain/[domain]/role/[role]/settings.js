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

import CollectionDetails from '../../../../../components/header/CollectionDetails';
import RequestUtils from '../../../../../components/utils/RequestUtils';
import RoleTabs from '../../../../../components/header/RoleTabs';
import NameHeader from '../../../../../components/header/NameHeader';
import Error from '../../../../_error';
import { selectDomainAuditEnabled } from '../../../../../redux/selectors/domainData';
import { selectIsLoading } from '../../../../../redux/selectors/loading';
import { selectRole } from '../../../../../redux/selectors/roles';
import { getDomainData } from '../../../../../redux/thunks/domain';
import { getRole } from '../../../../../redux/thunks/roles';
import { connect } from 'react-redux';
import SettingTable from '../../../../../components/settings/SettingTable';
import createCache from '@emotion/cache';
import { CacheProvider } from '@emotion/react';
import { ReduxPageLoader } from '../../../../../components/denali/ReduxPageLoader';

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
    const roles = await Promise.all([api.getForm()]).catch((err) => {
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
            roleName: context.query.role,
            userName: context.req.session.shortId,
            domainName: context.query.domain,
            _csrf: roles[0],
            nonce: context.req.headers.rid,
        },
    };
}

class SettingPage extends React.Component {
    constructor(props) {
        super(props);
        this.cache = createCache({
            key: 'athenz',
            nonce: this.props.nonce,
        });
        this.state = {
            error: null,
            reload: false,
        };
    }

    componentDidMount() {
        const { getRole, getDomainData, domainName, roleName, userName } =
            this.props;
        Promise.all([
            getDomainData(domainName, userName),
            getRole(domainName, roleName),
        ]).catch((err) => {
            let response = RequestUtils.errorCheckHelper(err);
            this.setState({
                error: response.error,
                reload: response.reload,
            });
        });
    }

    render() {
        const {
            domainName,
            reload,
            roleDetails,
            roleName,
            auditEnabled,
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

        return isLoading.includes('getDomainData') ? (
            <ReduxPageLoader message={'Loading domain data'} />
        ) : (
            <CacheProvider value={this.cache}>
                <div data-testid='setting'>
                    <Head>
                        <title>Athenz</title>
                    </Head>
                    <Header showSearch={true} />
                    <MainContentDiv>
                        <AppContainerDiv>
                            <RolesContainerDiv>
                                <RolesContentDiv>
                                    <PageHeaderDiv>
                                        <NameHeader
                                            category={'role'}
                                            domain={domainName}
                                            collection={roleName}
                                            collectionDetails={roleDetails}
                                        />
                                        <CollectionDetails
                                            collectionDetails={roleDetails}
                                            _csrf={_csrf}
                                        />
                                        <RoleTabs
                                            domain={domainName}
                                            role={roleName}
                                            selectedName={'settings'}
                                        />
                                    </PageHeaderDiv>
                                    <SettingTable
                                        domain={domainName}
                                        collection={roleName}
                                        collectionDetails={roleDetails}
                                        _csrf={_csrf}
                                        category={'role'}
                                    />
                                </RolesContentDiv>
                            </RolesContainerDiv>
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
        auditEnabled: selectDomainAuditEnabled(state),
        isLoading: selectIsLoading(state),
        roleDetails: selectRole(state, props.domainName, props.roleName),
    };
};

const mapDispatchToProps = (dispatch) => ({
    getDomainData: (domainName, userName) =>
        dispatch(getDomainData(domainName, userName)),
    getRole: (domainName, groupName) =>
        dispatch(getRole(domainName, groupName)),
});

export default connect(mapStateToProps, mapDispatchToProps)(SettingPage);
