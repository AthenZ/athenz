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
import { StaticWorkloadType } from '../../../components/constants/constants';
import IPTestUtils from '../../../tests_utils/IPTestUtils';
import { forEach } from 'async';

describe('StaticWorkloadType', () => {
    it('StaticWorkloadType should match the regex pattern based on types', () => {
        StaticWorkloadType.forEach((type) => {
            switch (type.value) {
                case 'VIP':
                    let vipName = IPTestUtils.generateRandomFQDN();
                    expect(vipName).toMatch(new RegExp(type.pattern));
                    break;
                case 'ENTERPRISE_APPLIANCE':
                    let enterpriseApplianceName =
                        IPTestUtils.generateRandomString(30);
                    expect(enterpriseApplianceName).toMatch(
                        new RegExp(type.pattern)
                    );
                    break;
                case 'CLOUD_LB':
                    let cloudLBName = IPTestUtils.generateRandomFQDN();
                    expect(cloudLBName).toMatch(new RegExp(type.pattern));
                    break;
                case 'CLOUD_NAT':
                    let cloudNATIP = IPTestUtils.generateRandomIP();
                    expect(cloudNATIP).toMatch(new RegExp(type.pattern));
                    break;
                case 'EXTERNAL_APPLIANCE':
                    let externalApplianceIP = IPTestUtils.generateRandomIP();
                    expect(externalApplianceIP).toMatch(
                        new RegExp(type.pattern)
                    );
                    let externalApplicationCIDR =
                        IPTestUtils.generateRandomCIDR();
                    expect(externalApplicationCIDR).toMatch(
                        new RegExp(type.pattern)
                    );
                    break;
                case 'CLOUD_MANAGED':
                    let externalCloudManagedName =
                        IPTestUtils.generateRandomFQDN();
                    expect(externalCloudManagedName).toMatch(
                        new RegExp(type.pattern)
                    );
                    break;
                case 'SERVICE_SUBNET':
                    let rfc1918CIDR = [
                        '10.0.0.0/8',
                        '10.1.2.0/24',
                        '172.16.0.0/12',
                        '172.16.1.0/24',
                        '172.31.0.0/16',
                        '192.168.0.0/16',
                        '192.168.1.0/24',
                        '192.168.2.0/24',
                        '192.168.100.0/24',
                        '10.255.255.0/24',
                    ];

                    let nonRFC1918CIDR = [
                        '8.8.8.0/24',
                        '203.0.113.0/24',
                        '198.51.100.0/24',
                        '192.0.2.0/24',
                        '0.0.0.0/0',
                        '224.0.0.0/4',
                        '240.0.0.0/4',
                        '169.254.0.0/16',
                        '198.18.0.0/15',
                    ];
                    forEach(rfc1918CIDR, (cidr) => {
                        expect(cidr).toMatch(new RegExp(type.pattern));
                    });
                    forEach(nonRFC1918CIDR, (cidr) => {
                        expect(cidr).not.toMatch(new RegExp(type.pattern));
                    });
                    break;
                default:
                    fail(`Unknown StaticWorkloadType: ${type.value}`);
            }
        });
    });
});
