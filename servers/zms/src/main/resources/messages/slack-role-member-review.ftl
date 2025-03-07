[
{
"type": "header",
"text": {
"type": "plain_text",
"text": ":athenz: Role Member Review Notification :clock1:",
"emoji": true
}
},
{
"type": "section",
"text": {
"type": "mrkdwn",
"text": "Review is required for the principals you manage in the listed roles.\n Review must be carried out by the domain administrators where your principal is referenced to satisfy governance and compliance requirements. Failure to extend the review dates will not cause your principals to lose any access.\n If the domain administrator has specified any details how to extend the review date, they will be included in the NOTES column.\n If the domain administrator has not specified any details, but the role is marked as a self-serve role, you can click on the role name and request an extension for your principals yourself using Athenz UI.\n Otherwise, no action is required from you and this email is for informational purposes only.",
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
    "text": "*Review:*\n${item["expirationOrReviewDate"]}"
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