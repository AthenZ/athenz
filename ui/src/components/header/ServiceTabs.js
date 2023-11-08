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
import {
    SERVICE_TABS,
    SERVICE_TYPE_DYNAMIC,
    SERVICE_TYPE_MICROSEGMENTATION,
    SERVICE_TYPE_STATIC,
} from '../constants/constants';

class ServiceTabs extends React.Component {
    constructor(props) {
        super(props);
        this.tabClicked = this.tabClicked.bind(this);
        this.state = {
            currTab: '',
        };
    }

    tabClicked(tab) {
        const { domain, service } = this.props;
        this.setState({ currTab: tab.name });
        switch (tab.name) {
            case 'static':
                this.props.router.push(
                    `/domain/${domain}/service/${service}/instance/static`,
                    `/domain/${domain}/service/${service}/instance/static`
                );
                break;
            case 'dynamic':
                this.props.router.push(
                    `/domain/${domain}/service/${service}/instance/dynamic`,
                    `/domain/${domain}/service/${service}/instance/dynamic`
                );
                break;
            case 'tags':
                this.props.router.push(
                    `/domain/${domain}/service/${service}/tags`,
                    `/domain/${domain}/service/${service}/tags`
                );
                break;
            case 'microsegmentation':
                this.props.router.push(
                    `/domain/${domain}/service/${service}/microsegmentation`,
                    `/domain/${domain}/service/${service}/microsegmentation`
                );
                break;
        }
    }

    render() {
        let shouldShowAllServiceTabs = this.props.featureFlag;
        let serviceTabs = shouldShowAllServiceTabs
            ? SERVICE_TABS
            : SERVICE_TABS.filter((tab) => tab.name === 'tags');
        return (
            <TabGroup
                tabs={serviceTabs}
                selectedName={this.props.selectedName}
                onClick={this.tabClicked}
                noanim
            />
        );
    }
}
export default withRouter(ServiceTabs);
