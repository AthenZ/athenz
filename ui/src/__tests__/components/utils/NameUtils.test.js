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
import NameUtils from '../../../components/utils/NameUtils';

describe('NameUtils', () => {
    it('should test', () => {
        let longname = 'home.test1';
        let shortname = NameUtils.getShortName('.', longname);
        let shortnamenotfound = NameUtils.getShortName(',', longname);
        let resource = 'test1:role';
        let resourcewithoutdomain = 'role';
        let getresource = NameUtils.getResourceName(resource, 'test1');
        let noresource = NameUtils.getResourceName(
            resourcewithoutdomain,
            'test1'
        );
        expect(shortname).toEqual('test1');
        expect(shortnamenotfound).toEqual('home.test1');
        expect(getresource).toEqual('test1:role');
        expect(noresource).toEqual('test1:role');

        let roleShort = NameUtils.getShortName(
            ':role.',
            'home.test:role.role1'
        );
        expect(roleShort).toEqual('role1');

        let policyShort = NameUtils.getShortName(
            ':policy.',
            'home.test:policy.policy.mytestpol'
        );
        expect(policyShort).toEqual('policy.mytestpol');
    });
});
