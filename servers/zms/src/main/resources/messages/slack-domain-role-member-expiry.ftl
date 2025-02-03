[
{
"type": "header",
"text": {
"type": "plain_text",
"text": ":clock1: Athenz Domain Role Member Expiration Notification :clock1:",
"emoji": true
}
},
{
"type": "section",
"text": {
"type": "mrkdwn",
"text": "You have one or more principals in your Athenz roles whose access will expire soon. Please review this list and, if necessary, login to *<${uiUrl}|Athenz UI>* to extend their expiration dates.",
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
    "text": "*<${item["collectionLink"]}|${item["domain"]}:role.${item["collection"]}>*"
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
    "text": "*Role:*\n<${item["collectionLink"]}|${item["collection"]}>"
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