\# Athenz ZMS AWS Domain Syncer

zms_syncer performs backup of Athenz domain data to a cloud repository.

--- Configuration Settings ---

\# The syncer state path directory, explicit or relative. Default is "/opt/zms_syncer".
\# If the path is relative, the ROOT will be prefixed. Else an explicit path is used as is.
\# example explicit: /opt/zms_syncer/
\# example relative: src/test/
state_path=<path to the state directory where the state file will be kept>

\# AWS specific attributes
\#
aws_bucket=<name of bucket in S3>

\# aws region default is "us-west-2"
aws_s3_region=<valid aws region>

\# Sets the amount of time to wait (in milliseconds) when initially establishing a connection
\# before giving up and timing out. A value of 0 means infinity, and is not recommended
\# Default = 5000
aws_connect_timeout=<milliseconds> 

\# Sets the amount of time to wait (in milliseconds) for the request to complete before giving
\# up and timing out. A non-positive value disables this feature.
\# Default = 5000
aws_request_timeout=<milliseconds>

\# The client credentials used to connect to aws using basic credentials
aws_cred_keyid=<aws credential keyid>
aws_cred_access_key=<aws credential access key>
