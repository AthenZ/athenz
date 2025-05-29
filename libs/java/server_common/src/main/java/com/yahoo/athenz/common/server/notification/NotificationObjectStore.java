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
package com.yahoo.athenz.common.server.notification;

import com.yahoo.athenz.common.server.ServerResourceException;

import java.util.List;

/*
 * Notification Object Store keeps track of which principals were
 * notified about which role and/or group reviews. This is
 * used to provide the list of roles/groups that a principal needs
 * review in the Athenz UI. The server must be responsible to keep
 * track of the notifications that were sent to each principal
 * and make sure to remove them from the review the list when the
 * role and/or group is reviewed. This should be done by best effort
 * and does not need absolute accuracy.
 */
public interface NotificationObjectStore {

    /*
     * Register the principal and the list of review objects (which is a list
     * of roles/groups) that the principal receives notifications for.
     * @param principalName the principal that received the notification
     * @param reviewObjects the list of review objects (roles/groups) that the principal
     * received notifications for (these are role and group Athenz Resource Names)
     * @throws ServerResourceException if there is an error while registering the principal
     */
    void registerReviewObjects(String principalName, List<String> reviewObjects) throws ServerResourceException;

    /*
     * Get the list of review objects (roles/groups) that the principal received notifications for.
     * @param principalName the principal to get the review objects for
     * @return the list of review objects (roles/groups) that the principal received notifications for
     * @throws ServerResourceException if there is an error while getting the review objects
     */
    List<String> getReviewObjects(String principalName) throws ServerResourceException;

    /*
     * Remove the principal and the list of review objects (roles/groups) that the principal
     * received notifications for.
     * @param principal the principal to remove
     * @throws ServerResourceException if there is an error while removing the principal
     */
    void removePrincipal(String principalName) throws ServerResourceException;

    /*
     * Remove the review object (role/group) that some principal received notifications for
     * because one of the principals has reviewed the object.
     * @param reviewObject the review objects (role/group) to remove (this is the role/group Athenz Resource Name)
     * @throws ServerResourceException if there is an error while removing the review object
     */
    void deregisterReviewObject(String reviewObject) throws ServerResourceException;
}
