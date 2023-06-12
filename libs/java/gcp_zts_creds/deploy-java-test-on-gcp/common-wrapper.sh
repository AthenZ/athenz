
MISSING_VARS=()
TEMP_LOG="$( mktemp )"
CONF_FILE="$PWD/common.yaml"

# Read a single entry from common.yaml into a bash-variable.
function makeSureVarSet() {
  local VAR_NAME="$1"
  local DEFAULT_VALUE="$2"
  local VAR_DESCRIPTION="$3"
  local VAR_VALUE
  VAR_VALUE="$(
      # Pretty ugly code to read a YAML value. Sorry.
      gawk --assign VAR_NAME="$VAR_NAME" '
          # Quoted values
          match($0, "^ *" VAR_NAME " *: *\"(.*)\" *(#.*)?", m) {
            print m[1];
            exit(0);
          }
          # Tagged values
          match($0, "^ *" VAR_NAME " *: *'"'"'(.*)'"'"' *(#.*)?", m) {
            print m[1];
            exit(0);
          }
          # Naked values.
          match($0, "^ *" VAR_NAME " *: *(.*) *(#.*)?", m) {
            print m[1];
            exit(0);
          }
        ' "$CONF_FILE"
    )"
  if [[ -z "$VAR_VALUE" ]] ; then
    VAR_VALUE="$DEFAULT_VALUE"
    if [[ "$DEFAULT_VALUE" == "???" ]] ; then
      MISSING_VARS=( "${MISSING_VARS[@]}" "$VAR_NAME" )
    fi
  else
    eval "$VAR_NAME=\"$VAR_VALUE\""
  fi
  echo "    $VAR_NAME=\"$VAR_VALUE\""$'\t'"# $VAR_DESCRIPTION" >> "$TEMP_LOG"
}

makeSureVarSet GCP_PROJECT_ID           "???" "GCP Project-ID"
makeSureVarSet GCP_REGION               "???" "GCP Region - e.g. us-west2"
makeSureVarSet GCP_FUNCTION_NAME        "???" "The created/updated GCP function's name"
makeSureVarSet ATHENZ_DOMAIN            "???" "Athenz domain"
makeSureVarSet ATHENZ_SERVICE           "???" "Athenz service"
makeSureVarSet ZTS_URL                  "???" "e.g. https://....:..../zts/v1"
makeSureVarSet GCP_VPC                  "???" "The GCP function's whole networking will be made through this VPC"
makeSureVarSet GCP_VPC_CONNECTOR_CIDR   "???" "The CIDR of the auto-created VPC-Connector from the GCP function to \$GCP_VPC"
makeSureVarSet GCP_VPC_CONNECTOR_ID     "???" "The name of the auto-created VPC-Connector from the GCP function to \$GCP_VPC"
makeSureVarSet CERT_DOMAIN              "???" "TODO: Abhijeet - explain what this is..."
makeSureVarSet CSR_COUNTRY              ""    "Created certificate's Subject field"
makeSureVarSet CSR_STATE                ""    "Created certificate's Subject field"
makeSureVarSet CSR_LOCALITY             ""    "Created certificate's Subject field"
makeSureVarSet CSR_ORGANIZATION         ""    "Created certificate's Subject field"
makeSureVarSet CSR_ORGANIZATION_UNIT    ""    "Created certificate's Subject field"

# Log all configurations.
echo "Configuration from $CONF_FILE :"
if which column 1>/dev/null 2>/dev/null ; then
  column -s $'\t' -t "$TEMP_LOG"
else
  cat "$TEMP_LOG"
fi
rm -f "$TEMP_LOG"

# Make sure all variables are set.
if (( "${#MISSING_VARS[@]}" > 0 )) ; then
    echo "ERROR: These entries are missing in $CONF_FILE :   ${MISSING_VARS[*]}" 1>&2
    false  # this will exit due to "set -e"
fi

# Create a temporary YAML file with all environment variables.
function createEnvVarsYamlFile() {
  local ENV_VARS_YAML
  ENV_VARS_YAML="$( mktemp /tmp/gcf-env-vars.yaml.XXXXXXXXXX )"
  echo "
      ATHENZ_DOMAIN: \"$ATHENZ_DOMAIN\"
      ATHENZ_SERVICE: \"$ATHENZ_SERVICE\"
      GCP_PROJECT_ID: \"$GCP_PROJECT_ID\"
      GCP_REGION: \"$GCP_REGION\"
      ZTS_URL: \"$ZTS_URL\"
      CERT_DOMAIN: \"$CERT_DOMAIN\"
      CSR_COUNTRY: \"$CSR_COUNTRY\"
      CSR_STATE: \"$CSR_STATE\"
      CSR_LOCALITY: \"$CSR_LOCALITY\"
      CSR_ORGANIZATION: \"$CSR_ORGANIZATION\"
      CSR_ORGANIZATION_UNIT: \"$CSR_ORGANIZATION_UNIT\"
    " > "$ENV_VARS_YAML"
    echo "$ENV_VARS_YAML"
}