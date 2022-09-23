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
import RoleTabs from '../../../../../components/header/RoleTabs';
import { selectIsLoading } from '../../../../../redux/selectors/loading';
import { getDomainData } from '../../../../../redux/thunks/domain';
import { connect } from 'react-redux';
import {
    selectRole,
    selectRoleTags,
} from '../../../../../redux/selectors/roles';
import { getRole } from '../../../../../redux/thunks/roles';
import TagList from '../../../../../components/tag/TagList';
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

const TagsContainerDiv = styled.div`
    align-items: stretch;
    flex: 1 1;
    height: calc(100vh - 60px);
    overflow: auto;
    display: flex;
    flex-direction: column;
`;

const TagsContentDiv = styled.div``;

const PageHeaderDiv = styled.div`
    background: linear-gradient(to top, #f2f2f2, #fff);
    padding: 20px 30px 0;
`;

export async function getServerSideProps(context) {
    let api = API(context.req);
    let reload = false;
    let notFound = false;
    let error = null;
    const tagsData = await Promise.all([api.getForm()]).catch((err) => {
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
            _csrf: tagsData[0],
            domainName: context.query.domain,
            nonce: context.req.headers.rid,
        },
    };
}

class RoleTagsPage extends React.Component {
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
        };
    }

    componentDidMount() {
        const { domainName, userName, getDomainData, roleName, getRole } =
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
            roleName,
            roleDetails,
            roleTags,
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
                <div data-testid='role-tags'>
                    <Head>
                        <title>Athenz Role Tags</title>
                    </Head>
                    <Header showSearch={true} />
                    <MainContentDiv>
                        <AppContainerDiv>
                            <TagsContainerDiv>
                                <TagsContentDiv>
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
                                            selectedName={'tags'}
                                        />
                                    </PageHeaderDiv>
                                    <TagList
                                        domain={domainName}
                                        collectionName={roleName}
                                        collectionDetails={roleDetails}
                                        tags={roleTags}
                                        category={'role'}
                                        _csrf={this.props._csrf}
                                    />
                                </TagsContentDiv>
                            </TagsContainerDiv>
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
        roleDetails: selectRole(state, props.domainName, props.roleName),
        roleTags: selectRoleTags(state, props.domainName, props.roleName),
    };
};

const mapDispatchToProps = (dispatch) => ({
    getDomainData: (domainName, userName) =>
        dispatch(getDomainData(domainName, userName)),
    getRole: (domainName, groupName) =>
        dispatch(getRole(domainName, groupName)),
});

export default connect(mapStateToProps, mapDispatchToProps)(RoleTagsPage);
