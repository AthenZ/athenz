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
import DomainDetails from '../../../components/header/DomainDetails';
import RequestUtils from '../../../components/utils/RequestUtils';
import Tabs from '../../../components/header/Tabs';
import Error from '../../_error';
import DomainNameHeader from '../../../components/header/DomainNameHeader';
import { connect } from 'react-redux';
import { getDomainData } from '../../../redux/thunks/domain';
import { getGroups } from '../../../redux/thunks/groups';
import GroupList from '../../../components/group/GroupList';
import { selectIsLoading } from '../../../redux/selectors/loading';
import { selectDomainData } from '../../../redux/selectors/domainData';
import Alert from '../../../components/denali/Alert';
import createCache from '@emotion/cache';
import { CacheProvider } from '@emotion/react';
import { ReduxPageLoader } from '../../../components/denali/ReduxPageLoader';
import { getAllUsers } from '../../../redux/thunks/user';
import { selectAllUsers } from '../../../redux/selectors/user';

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

const GroupsContainerDiv = styled.div`
    align-items: stretch;
    flex: 1 1;
    height: calc(100vh - 60px);
    overflow: auto;
    display: flex;
    flex-direction: column;
`;

const GroupsContentDiv = styled.div``;

const PageHeaderDiv = styled.div`
    background: linear-gradient(to top, #f2f2f2, #fff);
    padding: 20px 30px 0;
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

class GroupPage extends React.Component {
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
        const {
            getAllUsers,
            getDomainData,
            getGroupsList,
            domainName,
            userName,
        } = this.props;
        Promise.all([
            getAllUsers(),
            getDomainData(domainName, userName),
            getGroupsList(domainName),
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
        const { reload, _csrf, domainData, isLoading, domainName } = this.props;
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
                <div data-testid='group'>
                    <Head>
                        <title>Athenz</title>
                    </Head>
                    <Header showSearch={true} />
                    <MainContentDiv>
                        <AppContainerDiv>
                            <GroupsContainerDiv>
                                <GroupsContentDiv>
                                    <PageHeaderDiv>
                                        <DomainNameHeader
                                            domainName={domainName}
                                        />
                                        <DomainDetails
                                            api={this.api}
                                            _csrf={_csrf}
                                        />
                                        <Tabs
                                            domain={domainName}
                                            selectedName={'groups'}
                                        />
                                    </PageHeaderDiv>
                                    <GroupList
                                        domain={domainName}
                                        _csrf={_csrf}
                                    />
                                </GroupsContentDiv>
                            </GroupsContainerDiv>
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
        domainData: selectDomainData(state),
        isLoading: selectIsLoading(state),
        userList: selectAllUsers(state),
    };
};

const mapDispatchToProps = (dispatch) => ({
    getAllUsers: () => dispatch(getAllUsers()),
    getDomainData: (domainName, userName) =>
        dispatch(getDomainData(domainName, userName)),
    getGroupsList: (domainName) => dispatch(getGroups(domainName)),
});

export default connect(mapStateToProps, mapDispatchToProps)(GroupPage);
