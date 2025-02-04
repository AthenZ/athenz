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
package com.yahoo.athenz.common.notification.slack;

public final class SlackNotificationConsts {

    public static final String SLACK_BOT_TOKEN_APP_NAME = "athenz.notification_slack.token_app_name";
    public static final String SLACK_BOT_TOKEN_KEYGROUP_NAME = "athenz.notification_slack.token_keygroup_name";
    public static final String SLACK_BOT_TOKEN_KEY_NAME = "athenz.notification_slack.token_key_names";
    public static final String SLACK_CLIENT_MAX_RETRIES = "athenz.notification_slack.max_retries";
    public static final String SLACK_CLIENT_RATE_LIMIT_DELAY = "athenz.notification_slack.rate_limit_delay_ms";
    public static final String PROP_SLACK_FETCH_TOKEN_PERIOD_BETWEEN_EXECUTIONS = "athenz.notification_slack.period_between_fetch_token_executions_seconds";
    public static final String DEFAULT_SLACK_FETCH_TOKEN_PERIOD_BETWEEN_EXECUTIONS = "3600";
    public static final String SLACK_API_INVALID_AUTH_ERROR = "invalid_auth";
    public static final String SLACK_API_RATE_LIMIT_ERROR = "rate_limited";
    public static final Integer SLACK_API_RATE_LIMIT_CODE = 429;
    // prevent object creation
    private SlackNotificationConsts() {
    }
}
