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
import moment from 'moment-timezone';
import { _ } from 'lodash';
import {
    getSmallestExpiryOrReview,
    isReviewRequired,
} from '../../../components/utils/ReviewUtils';

describe('ReviewUtils', (object, method) => {

    afterAll(() => {
        jest.clearAllMocks();
    });


    it('getSmallestExpiryOrReview check memberExpiryDays value is picked up', async () => {
        const role = { memberExpiryDays: 5, lastReviewedDate: '2024-07-24T10:58:07.533Z' };
        let actualDays = getSmallestExpiryOrReview(role);

        expect(_.isEqual(role.memberExpiryDays, actualDays)).toBeTruthy();
    });

    it('getSmallestExpiryOrReview check serviceExpiryDays value is picked up', async () => {
        const role = { serviceExpiryDays: 9, lastReviewedDate: '2024-07-24T10:58:07.533Z' };
        let actualDays = getSmallestExpiryOrReview(role);

        expect(_.isEqual(role.serviceExpiryDays, actualDays)).toBeTruthy();
    });

    it('getSmallestExpiryOrReview check memberReviewDays value is picked up', async () => {
        const role = { memberReviewDays: 6, lastReviewedDate: '2024-07-24T10:58:07.533Z' };
        let actualDays = getSmallestExpiryOrReview(role);

        expect(_.isEqual(role.memberReviewDays, actualDays)).toBeTruthy();
    });

    it('getSmallestExpiryOrReview check serviceReviewDays value is picked up', async () => {
        const role = { serviceReviewDays: 10, lastReviewedDate: '2024-07-24T10:58:07.533Z' };
        let actualDays = getSmallestExpiryOrReview(role);

        expect(_.isEqual(role.serviceReviewDays, actualDays)).toBeTruthy();
    });

    it('getSmallestExpiryOrReview check groupReviewDays value is picked up', async () => {
        const role = { groupReviewDays: 8, lastReviewedDate: '2024-07-24T10:58:07.533Z' };
        let actualDays = getSmallestExpiryOrReview(role);

        expect(_.isEqual(role.groupReviewDays, actualDays)).toBeTruthy();
    });

    it('getSmallestExpiryOrReview check groupExpiryDays value is picked up', async () => {
        const role = { groupExpiryDays: 7, lastReviewedDate: '2024-07-24T10:58:07.533Z' };
        let actualDays = getSmallestExpiryOrReview(role);

        expect(_.isEqual(role.groupExpiryDays, actualDays)).toBeTruthy();
    });

    it("getSmallestExpiryOrReview check smallest value picked, non 0, null doesn't produce error", async () => {
        const role = {
            memberExpiryDays: 0,
            serviceExpiryDays: null,
            memberReviewDays: 6,
            serviceReviewDays: 10,
            groupReviewDays: 8,
            groupExpiryDays: 7,
            lastReviewedDate: '2024-07-24T10:58:07.533Z'
        };
        let actualDays = getSmallestExpiryOrReview(role);

        expect(_.isEqual(role.memberReviewDays, actualDays)).toBeTruthy();
    });

    it("getSmallestExpiryOrReview when no expiry or review days assigned to the role, return 0", async () => {
        const role = {
            lastReviewedDate: '2024-07-24T10:58:07.533Z'
        };
        let actualDays = getSmallestExpiryOrReview(role);

        expect(_.isEqual(0, actualDays)).toBeTruthy();
    });

    it("isReviewRequired when no expiry or review days assigned to the role, return false", async () => {
        const role = {};
        let reviewRequired = isReviewRequired(role);

        expect(_.isEqual(false, reviewRequired)).toBeTruthy();
    });

    it("isReviewRequired when lastReviewDate is more than 80% of memberExpiryDate ago - return true", async () => {
        const role = {
            lastReviewedDate: '2024-07-01T11:59:59.000Z',
            memberExpiryDays: '10'
        };
        // mock current date
        jest.spyOn(moment.prototype, 'utc')
            .mockReturnValue(moment('2024-07-09T12:00:00.000Z').utc());

        let reviewRequired = isReviewRequired(role);

        expect(_.isEqual(true, reviewRequired)).toBeTruthy();
    });

    it("isReviewRequired when lastReviewDate is less than 80% of memberExpiryDate ago - return false", async () => {
        const role = {
            lastReviewedDate: '2024-07-01T12:00:01.000Z',
            memberExpiryDays: '10'
        };
        // mock current date
        // jest.spyOn(moment.prototype, 'utc')
        //     .mockReturnValue(moment('2024-07-09T12:00:00.000Z').utc());

        let reviewRequired = isReviewRequired(role);

        expect(_.isEqual(false, reviewRequired)).toBeTruthy();
    });
});
