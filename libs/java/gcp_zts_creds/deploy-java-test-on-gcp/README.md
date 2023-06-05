# Deploy a test GCF (Google Cloud Function) that gets SIA certs

1. Edit configurations at [common.yaml](common.yaml)  (just skip this to get an error message that explains what should contain)
2. Execute [gcf-re-deploy.sh](gcf-re-deploy.sh) to deploy the GCF.
3. Execute [gcf-execute-via-curl.sh](gcf-execute-via-curl.sh) to make an HTTP request to trigger the GCF. All the GCF's logs will be shown.
4. Optionally, execute [gcf-view-logs.sh](gcf-view-logs.sh) to see all logs. 
