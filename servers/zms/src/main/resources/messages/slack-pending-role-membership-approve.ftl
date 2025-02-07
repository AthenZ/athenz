[
{
"type": "header",
"text": {
"type": "plain_text",
"text": ":athenz: Pending Membership Approved Details",
"emoji": true
}
},
{
"type": "section",
"text": {
"type": "mrkdwn",
"text": "Please find below the details of the decision regarding the pending role member:",
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
"text": "*<${roleLink}|${domain}:role.${role}>*"
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
"text": "*Role:*\n<${roleLink}|${role}>"
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
"text": "*Approved By:*\n${actionPrincipal}"
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