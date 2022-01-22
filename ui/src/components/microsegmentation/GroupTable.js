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
import GraphicalServiceRow from './GraphicalServiceRow';

const StyleTable = styled.table`
    width: 100%;
    border-spacing: 0 15px;
    display: table;
    border-collapse: separate;
    border-color: grey;
`;

export default class GroupTable extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
    }

    render() {
        const { data } = this.props;
        let rows = [];

        const serviceMap = new Map();

        for (let rule of data['inbound']) {
            let newRule = JSON.parse(JSON.stringify(rule));
            let svcName = newRule['destination_service'];
            delete newRule['destination_service'];
            newRule['category'] = 'inbound';

            if (serviceMap.get(svcName)) {
                let currentData = serviceMap.get(svcName);
                currentData.push(newRule);
            } else {
                serviceMap.set(svcName, [newRule]);
            }
        }

        for (let rule of data['outbound']) {
            let newRule = JSON.parse(JSON.stringify(rule));
            let svcName = newRule['source_service'];
            delete newRule['source_service'];
            newRule['category'] = 'outbound';

            if (serviceMap.get(svcName)) {
                let currentData = serviceMap.get(svcName);
                currentData.push(newRule);
            } else {
                serviceMap.set(svcName, [newRule]);
            }
        }

        for (const [key, value] of serviceMap.entries()) {
            let name = key;
            rows.push(
                <GraphicalServiceRow
                    id={name}
                    name={name}
                    api={this.api}
                    key={name}
                    _csrf={this.props._csrf}
                    data={value}
                    domain={this.props.domain}
                    onDeleteCondition={this.props.onSubmit}
                />
            );
        }

        return (
            <StyleTable data-testid='segmentation-rule-table'>
                <tbody>{rows}</tbody>
            </StyleTable>
        );
    }
}
