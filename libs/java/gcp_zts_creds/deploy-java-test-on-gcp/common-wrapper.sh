
MISSING_VARS=()
TEMP_LOG="$( mktemp )"
CONF_FILE="$PWD/common.yaml"

# Read a single entry from common.yaml into a bash-variable.
function makeSureVarSet() {
  local VAR_NAME="$1"
  local VAR_DESCRIPTION="$2"
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
    VAR_VALUE="???"
    MISSING_VARS=( "${MISSING_VARS[@]}" "$VAR_NAME" )
  else
    eval "$VAR_NAME=\"$VAR_VALUE\""
  fi
  echo "    $VAR_NAME=\"$VAR_VALUE\""$'\t'"# $VAR_DESCRIPTION" >> "$TEMP_LOG"
}

makeSureVarSet GCP_PROJECT_ID           "GCP Project-ID"
makeSureVarSet GCP_REGION               "GCP Region - e.g. us-west2"
makeSureVarSet GCP_FUNCTION_NAME        "The created/updated GCP function's name"
makeSureVarSet ATHENZ_DOMAIN            "Athenz domain"
makeSureVarSet ATHENZ_SERVICE           "Athenz service"
makeSureVarSet ZTS_URL                  "e.g. https://....:..../zts/v1"
makeSureVarSet GCP_VPC                  "The GCP function's whole networking will be made through this VPC"
makeSureVarSet GCP_VPC_CONNECTOR_CIDR   "The CIDR of the auto-created VPC-Connector from the GCP function to \$GCP_VPC"
makeSureVarSet GCP_VPC_CONNECTOR_ID     "The name of the auto-created VPC-Connector from the GCP function to \$GCP_VPC"

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
