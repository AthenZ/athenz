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

export default class IPTestUtils {
    static getRandomInt(min, max) {
        return Math.floor(Math.random() * (max - min + 1)) + min;
    }

    static generateRandomIP() {
        return `${IPTestUtils.getRandomInt(0, 255)}.${IPTestUtils.getRandomInt(
            0,
            255
        )}.${IPTestUtils.getRandomInt(0, 255)}.${IPTestUtils.getRandomInt(
            0,
            255
        )}`;
    }

    static generateRandomCIDR() {
        const ip = IPTestUtils.generateRandomIP();
        const prefix = IPTestUtils.getRandomInt(0, 32);
        return `${ip}/${prefix}`;
    }

    static generateRandomString(length) {
        const characters =
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        let result = '';
        for (let i = 0; i < length; i++) {
            result += characters.charAt(
                Math.floor(Math.random() * characters.length)
            );
        }
        return result;
    }

    static generateRandomFQDN() {
        const subdomain = IPTestUtils.generateRandomString(
            IPTestUtils.getRandomInt(3, 10)
        );
        const domain = IPTestUtils.generateRandomString(
            IPTestUtils.getRandomInt(3, 10)
        );
        const tld = IPTestUtils.generateRandomString(
            IPTestUtils.getRandomInt(2, 6)
        ); // Top Level Domain, like com, net, org, etc.
        return `${subdomain}.${domain}.${tld}`;
    }
}
