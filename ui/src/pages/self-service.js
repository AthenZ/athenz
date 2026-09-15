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
import styled from '@emotion/styled';
import { CacheProvider } from '@emotion/react';
import createCache from '@emotion/cache';
import { connect } from 'react-redux';
import Error from './_error';
import RequestUtils from '../components/utils/RequestUtils';
import API from '../api';
import { getHeaderDetails } from '../redux/thunks/domains';
import SelfServiceView from '../components/self-service/SelfServiceView';

const PageWrap = styled.div`
    display: flex;
    flex-direction: column;
    min-height: 100%;
`;

export async function getServerSideProps(context) {
    let api = API(context.req);
    let reload = false;
    let error = null;
    const form = await Promise.all([api.getForm()]).catch((err) => {
        let response = RequestUtils.errorCheckHelper(err);
        reload = response.reload;
        error = response.error;
        return [''];
    });
    return {
        props: {
            reload,
            error,
            _csrf: form[0],
            nonce: context.req && context.req.headers.rid,
            userName: context.req.session.shortId,
        },
    };
}

class PageSelfService extends React.Component {
    constructor(props) {
        super(props);
        this.cache = createCache({
            key: 'athenz',
            nonce: this.props.nonce,
        });
    }

    componentDidMount() {
        this.props.getHeaderDetails();
    }

    render() {
        if (this.props.reload) {
            window.location.reload();
            return <div />;
        }
        if (this.props.error) {
            return <Error err={this.props.error} />;
        }
        return (
            <CacheProvider value={this.cache}>
                <PageWrap>
                    <SelfServiceView
                        userName={this.props.userName}
                        _csrf={this.props._csrf}
                    />
                </PageWrap>
            </CacheProvider>
        );
    }
}

const mapStateToProps = (state, props) => ({
    ...props,
});

const mapDispatchToProps = (dispatch) => ({
    getHeaderDetails: () => dispatch(getHeaderDetails()),
});

export default connect(mapStateToProps, mapDispatchToProps)(PageSelfService);
