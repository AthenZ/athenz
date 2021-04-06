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
import TabGroup from '../denali/TabGroup';
import { withRouter } from 'next/router';
import { SERVICE_TABS } from '../constants/constants';

class ServiceTabs extends React.Component {
    constructor(props) {
        super(props);
        this.tabClicked = this.tabClicked.bind(this);
    }

    tabClicked(tab) {
        const { domain, service } = this.props;
        switch (tab.name) {
            case 'static':
                this.props.router.push(
                    `/domain/${domain}/service/${service}/instance/static`,
                    `/domain/${domain}/service/${service}/instance/static`,
                    { getInitialProps: true }
                );
                break;
            case 'dynamic':
                this.props.router.push(
                    `/domain/${domain}/service/${service}/instance/dynamic`,
                    `/domain/${domain}/service/${service}/instance/dynamic`,
                    { getInitialProps: true }
                );
                break;
        }
    }

    render() {
        return (
            <TabGroup
                tabs={SERVICE_TABS}
                selectedName={this.props.selectedName}
                onClick={this.tabClicked}
                noanim
            />
        );
    }
}
export default withRouter(ServiceTabs);
