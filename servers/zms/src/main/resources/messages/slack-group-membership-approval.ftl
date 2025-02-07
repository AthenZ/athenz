[
{
"type": "header",
"text": {
"type": "plain_text",
"text": ":athenz: Group Membership Approval Details",
"emoji": true
}
},
{
"type": "section",
"text": {
"type": "mrkdwn",
"text": "Please visit the <${workflowLink!''}|Athenz Membership Review Page> to act on this request that has been submitted with the following details:",
"verbatim": false
}
},
{
"type": "divider"
},
{
"type": "section",
"fields": [
{
"type": "mrkdwn",
"text": "*Domain:*\n<${domainLink!''}|${domain!''}>"
},
{
"type": "mrkdwn",
"text": "*Group:*\n<${groupLink!''}|${group!''}>"
},
{
"type": "mrkdwn",
"text": "*Member:*\n${member!''}"
},
{
"type": "mrkdwn",
"text": "*Requestor:*\n${requester!''}"
},
{
"type": "mrkdwn",
"text": "*Reason:*\n${reason!''}"
}
]
},
{
"type": "divider"
}
]