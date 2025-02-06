[
{
"type": "header",
"text": {
"type": "plain_text",
"text": ":athenz: Pending Group Membership Approved Details",
"emoji": true
}
},
{
"type": "section",
"text": {
"type": "mrkdwn",
"text": "Please find below the details of the decision regarding the pending group member:",
"verbatim": false
}
},
{
"type": "divider"
},
{
"type": "section",
"text": {
"type": "mrkdwn",
"text": "*<${groupLink}|${domain}:group.${group}>*"
}
},
{
"type": "section",
"fields": [
{
"type": "mrkdwn",
"text": "*Domain:*\n<${domainLink}|${domain}>"
},
{
"type": "mrkdwn",
"text": "*Group:*\n<${groupLink}|${group}>"
},
{
"type": "mrkdwn",
"text": "*Member:*\n${member}"
},
{
"type": "mrkdwn",
"text": "*Requestor:*\n${requester!''}"
},
{
"type": "mrkdwn",
"text": "*Pending Operation:*\n${pendingState!''}"
},
{
"type": "mrkdwn",
"text": "*Approved By:*\n${actionPrincipal!''}"
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