#!/bin/bash -e
set -o pipefail

cd "$( dirname "$0" )"
. common-wrapper.sh

# Log header and footer.
echo
echo "============================== DEPLOY =============================="
echo
trap '
    echo
    echo "===================================================================="
    echo
  ' EXIT

# Ensure the Serverless VPC Access API is enabled for your project:
#  gcloud components update
#  gcloud services enable vpcaccess.googleapis.com

# tagKeys/281475731317309  sec-ignore-cmek-encryption
#    Bypass Organization Policy Enforcement for Baseline SBC-GCP-4007, SBC-GCP-5003, and SBC-GCP-7002.
# Bypass:    gcloud resource-manager tags bindings create --tag-value=tagValues/281484611371492 --parent=//cloudresourcemanager.googleapis.com/projects/gcp-calypso-nonprod
# Default:   gcloud resource-manager tags bindings delete --tag-value=tagValues/281484611371492 --parent=//cloudresourcemanager.googleapis.com/projects/gcp-calypso-nonprod


#  # ===================================    VPC CONNECTOR    ===================================
#
#  echo "Make sure a VPC-Connector \"$GCP_VPC_CONNECTOR_ID\" exists"
#  if ! ( set -x ; gcloud compute networks vpc-access connectors list --region "$GCP_REGION" )| grep -q "^$GCP_VPC_CONNECTOR_ID " ; then
#    echo "Creating VPC-Connector, so all networking of the Cloud-Function go through it"
#    (
#      set -x
#      gcloud compute networks vpc-access connectors create "$GCP_VPC_CONNECTOR_ID" \
#          --network="$GCP_VPC" \
#          --region "$GCP_REGION" \
#          --range="$GCP_VPC_CONNECTOR_CIDR"
#    )
#  fi
#  echo
#
#  # ===================================    VPC NAT    ===================================
#
#  # The Cloud-Function can't access the internet (specifically - can't access ZTS) using its default IP,
#  #  because that default IP is used by multiple tenants: one day, when ATHENZ will want to validate the client's IP,
#  #  it must only accept IPs that belong to a specific tenant.
#  # This means that the Cloud-Function MUST use a VPC-Connector (with egress=all): the VPC's NAT's IP is OK.
#  # It also means that the VPC must have a NAT.
#  # We will now make sure that such NAT exists.
#  echo "Make sure that VPC \"$GCP_VPC\" has a NAT on region \"$GCP_REGION\""
#  NATS_REPORT="$(
#      ( set -x ; gcloud compute routers list --format json ) |
#      jq -r --arg OUR_REGION "$GCP_REGION" --arg OUR_VPC "$GCP_VPC" '
#          .[] |
#          .name as $ROUTER_NAME |
#          ( .network | sub(".*\/"; "") ) as $VPC |
#          ( .region | sub(".*\/"; "") ) as $REGION |
#          .nats = if (.nats == null) then [ { name: "-" } ] else .nats end |
#          .nats[] |
#          .name as $NAT_NAME |
#          .natIps = if (.natIps == null) then [ "-" ] else .natIps end |
#          .natIps[] |
#          (
#            if ($REGION == $OUR_REGION) and ($VPC == $OUR_VPC) then
#              "\t<=== THIS WILL BE USED"
#            else
#              ""
#            end
#          ) as $COMMENT |
#          ( $ROUTER_NAME + "\t" + $NAT_NAME + "\t" + $VPC + "\t" + $REGION + $COMMENT )
#        '
#    )"
#  echo $'Router\tNAT\tVPC\tRegion\n'"$NATS_REPORT" | column -t -s $'\t'
#  echo
#  if ! echo "$NATS_REPORT" | grep -q "THIS WILL BE USED" ; then
#    echo "ERROR: Please make sure the vpc \"$GCP_VPC\" has a NAT in region \"$GCP_REGION\"" 1>&2
#    false
#  fi

# ===================================    DEPLOY    ===================================

# See https://cloud.google.com/functions/docs/concepts/nodejs-runtime

echo "Deploying Cloud-Function..."
SERVICE_ACCOUNT="$ATHENZ_SERVICE@$GCP_PROJECT_ID.iam.gserviceaccount.com"
(
  set -x
  time gcloud functions deploy "$GCP_FUNCTION_NAME" \
      --trigger-http \
      --allow-unauthenticated \
      --serve-all-traffic-latest-revision \
      --run-service-account "$SERVICE_ACCOUNT" \
      --service-account "$SERVICE_ACCOUNT" \
      --region "$GCP_REGION" \
      --vpc-connector "$GCP_VPC_CONNECTOR_ID" \
      --egress-settings "all" \
      --env-vars-file "$( createEnvVarsYamlFile )" \
      --entry-point GcfSiaTest \
      --runtime nodejs18 \
      --memory=256M \
)
echo
