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
import { PERCENTAGE_OF_DAYS_TILL_NEXT_REVIEW } from '../constants/constants';
import moment from 'moment-timezone';

export function isReviewRequired(roleOrGroup) {
    // determine last review or last modified date
    const reviewData = roleOrGroup.lastReviewedDate
        ? { lastReviewedDate: roleOrGroup.lastReviewedDate }
        : { lastReviewedDate: roleOrGroup.modified };
    // get smallest expiry or review days value for the role
    const smallestExpiryOrReview = getSmallestExpiryOrReview(roleOrGroup);

    if (smallestExpiryOrReview === 0) {
        // review or expiry days were not set in settings - no review required
        return false;
    }

    // get 20% of the smallest review period
    reviewData.pct20 = Math.ceil(
        smallestExpiryOrReview * PERCENTAGE_OF_DAYS_TILL_NEXT_REVIEW
    );

    const lastReviewedDate = moment(
        reviewData.lastReviewedDate,
        'YYYY-MM-DDTHH:mm:ss.SSSZ'
    );
    const now = moment().utc();

    // check if expiry/review is coming up within 20% of the smallest review/expiry period
    return now
        .subtract(smallestExpiryOrReview, 'days')
        .add(reviewData.pct20, 'days')
        .isAfter(lastReviewedDate);
}

export function domainExpirationIsConfigured(domain) {
    return (
        !!domain?.memberExpiryDays ||
        !!domain?.groupExpiryDays ||
        !!domain?.serviceExpiryDays
    );
}

export function roleExpirationIsConfigured(roleDetails) {
    return (
        !!roleDetails?.memberExpiryDays ||
        !!roleDetails?.memberReviewDays ||
        !!roleDetails?.groupExpiryDays ||
        !!roleDetails?.groupReviewDays ||
        !!roleDetails?.serviceExpiryDays ||
        !!roleDetails?.serviceReviewDays
    );
}

export function getExpirationFromDomain(domainData) {
    return {
        groupExpiryDays: Number(domainData?.groupExpiryDays) || 0,
        memberExpiryDays: Number(domainData?.memberExpiryDays) || 0,
        serviceExpiryDays: Number(domainData?.serviceExpiryDays) || 0,
    };
}

export function getSmallestExpiryOrReview(roleOrGroup) {
    const values = [
        roleOrGroup?.memberExpiryDays || 0,
        roleOrGroup?.memberReviewDays || 0,
        roleOrGroup?.groupExpiryDays || 0,
        roleOrGroup?.groupReviewDays || 0,
        roleOrGroup?.serviceExpiryDays || 0,
        roleOrGroup?.serviceReviewDays || 0,
    ].filter((obj) => obj > 0); // pick only those that have days set and days > 0

    if (values.length > 0) {
        // pick the one with the smallest days value
        return values.reduce((obj1, obj2) => (obj1 < obj2 ? obj1 : obj2));
    }
    return 0;
}
