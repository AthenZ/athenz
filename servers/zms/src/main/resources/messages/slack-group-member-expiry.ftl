[
{
"type": "header",
"text": {
"type": "plain_text",
"text": ":athenz: Group Member Expiration Notification :clock1:",
"emoji": true
}
},
{
"type": "section",
"text": {
"type": "mrkdwn",
"text": "Access for the principals you manage in the listed groups will expire soon. Failure to extend the expiry for these principals before the listed date will cause these principals to lose access to the configured resources and likely result in a production incident.\n Please review this list and, if necessary, follow up with their respective domain administrators to extend those expiration dates.\n If the domain administrator has specified any details how to extend the expiry, they will be included in the NOTES column.\n If the domain administrator has not specified any details, but the group is marked as a self-serve group, you can click on the group name and request an extension for your principals yourself using Athenz UI.",
"verbatim": false
}
},
{
"type": "divider"
}
<#list collectionData as item>
    ,{
    "type": "section",
    "text": {
    "type": "mrkdwn",
    "text": "*<${item["collectionLink"]}|${item["domain"]}:group.${item["collection"]}>*"
    }
    },
    {
    "type": "section",
    "fields": [
    {
    "type": "mrkdwn",
    "text": "*Domain:*\n<${item["domainLink"]}|${item["domain"]}>"
    },
    {
    "type": "mrkdwn",
    "text": "*Expiration:*\n${item["expirationOrReviewDate"]}"
    },
    {
    "type": "mrkdwn",
    "text": "*Group:*\n<${item["collectionLink"]}|${item["collection"]}>"
    },
    {
    "type": "mrkdwn",
    "text": "*Member:*\n${item["member"]}"
    }
    <#if item["notes"]?has_content>
        ,{
        "type": "mrkdwn",
        "text": "*Notes:*\n${item["notes"]}"
        }
    </#if>
    ]
    },
    {
    "type": "divider"
    }
</#list>
]