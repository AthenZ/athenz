# Deploy a GCF (Google Cloud Function) to that gets SIA certs

1. Edit configurations at [common.sh](common.sh)
2. Execute [gcf-re-deploy.sh](gcf-re-deploy.sh) to deploy the GCF.
3. Execute [gcf-execute-via-curl.sh](gcf-execute-via-curl.sh) to make an HTTP request to trigger the GCF. All the GCF's logs will be shown.
4. Optionally, execute [gcf-view-logs.sh](gcf-view-logs.sh) to see all logs. 
