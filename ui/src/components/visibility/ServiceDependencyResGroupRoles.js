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
import Link from 'next/link';
import Tag from '../denali/Tag';

export default class ServiceDependencyResGroupRoles extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            details: props.details,
            expanded: false,
        };
        this.expandRoles = this.expandRoles.bind(this);
    }

    expandRoles() {
        this.setState({
            expanded: !this.state.expanded,
        });
    }

    render() {
        let toReturn = [];
        let length = this.state.details ? this.state.details.length : 0;
        const MAX_GROUPS_DISPLAYED = 3;
        let maxNumberOfResgroupsDisplayed =
            length > MAX_GROUPS_DISPLAYED ? MAX_GROUPS_DISPLAYED : length;

        // Show resource group roles. Clicking on them will redirect to the designated role.
        for (let i = 0; i < maxNumberOfResgroupsDisplayed; i++) {
            let roleEntry = this.state.details[i];
            toReturn.push(
                <Tag
                    key={
                        roleEntry.resourceGroup +
                        ';' +
                        roleEntry.resourceGroupRole
                    }
                >
                    <Link href={roleEntry.roleLink} style={{ textDecoration: 'none' }}>
                        {roleEntry.resourceGroupRole}
                    </Link>
                    {'  '}
                </Tag>
            );
            length--;
        }

        // If there are more than MAX_GROUPS_DISPLAYED roles, the others will be hidden.
        // We'll add a +# tag that can be clicked to make the rest of the roles appear
        if (length > 0) {
            toReturn.push(
                <Tag
                    key={this.state.details[0].resourceGroup + ';showMore'}
                    onClick={() => this.expandRoles()}
                >
                    +{length}
                </Tag>
            );
            if (this.state.expanded) {
                toReturn.push(<br />);
                for (
                    let i = maxNumberOfResgroupsDisplayed;
                    i < this.state.details.length;
                    i++
                ) {
                    let roleEntry = this.state.details[i];
                    toReturn.push(
                        <Tag
                            key={
                                roleEntry.resourceGroup +
                                ';' +
                                roleEntry.resourceGroupRole
                            }
                        >
                            <Link href={roleEntry.roleLink} style={{ textDecoration: 'none' }}>
                                {roleEntry.resourceGroupRole}
                            </Link>
                            {'  '}
                        </Tag>
                    );
                    length--;
                }
            }
        }
        return toReturn;
    }
}
