
export GCP_PROJECT_ID="gcp-calypso-nonprod"
export GCP_REGION="us-west1"
export GCP_FUNCTION_NAME="gbendor_test_function"
export ATHENZ_DOMAIN="calypso.nonprod"
export ATHENZ_SERVICE="bastion"
export ZTS_URL="https://zts.athenz.ouroath.com:4443/zts/v1"

export GCP_VPC="calypso-nonprod-vpc"
export GCP_VPC_CONNECTOR_CIDR="10.250.250.0/28"
export GCP_VPC_CONNECTOR_ID="gbendor-test-connector"

export SERVICE_ACCOUNT="$ATHENZ_SERVICE@$GCP_PROJECT_ID.iam.gserviceaccount.com"
