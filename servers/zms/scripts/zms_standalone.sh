#!/bin/bash
#############
# Usage: See display_usage
# Requires zms.war and various system property files and must run as root or sudo user
# Assumes that this run on AWS.
###############

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

display_usage() {
    echo "zms_standalone.sh -z [zms war file name] -o [private/pub key output directory] -c [command] -d [domain name] -s [service name] -k [key id] -l [additional classpath folder] -r [root folder for properties files]";
    echo "example: zms_standalone.sh -z zms.war -o /var/run/zms_server/keys -c put-public-key -d sys.auth -s zms -k 1234 -r /home/athenz"
    echo "example: zms_standalone.sh -z zms.war -c delete-public-key -d sys.auth -s zms -k 1234 -r /home/athenz"
}

tmp_zms_dir=/tmp/zms
ZMS_BOOTSTRAP_CLASS=com.yahoo.athenz.zms.ZMSImplMain

setJavaOpts() {
    ROOT=$1
    JAVA_OPTS="${JAVA_OPTS} -Dathenz.prop_file=${ROOT}/conf/zms_server/athenz.properties"
    JAVA_OPTS="${JAVA_OPTS} -Dathenz.zms.prop_file=${ROOT}/conf/zms_server/zms.properties"
    JAVA_OPTS="${JAVA_OPTS} -Dlogback.configurationFile=${ROOT}/conf/zms_server/logback.xml"
}

makeTempDir() {
    if [ ! -d "$tmp_zms_dir" ]; then
        mkdir $tmp_zms_dir
    fi
}

cleanup() {
    rm -r -f $tmp_zms_dir/*
}

generateKeys() {
    key_dir=$1
    openssl genrsa -out $key_dir/private.pem 2048
    chmod 600 $key_dir/private.pem
    openssl rsa -in $key_dir/private.pem -pubout > $key_dir/public.pem
}

executeZMSImplMain() {
    ZMS_CLASSPATH="lib/*:classes/.:${add_class_path}/*"
    cp $zms_war $tmp_zms_dir/

    #untar zms.war
    cd $tmp_zms_dir

    jar -xf *.war

    cd WEB-INF/
    java -classpath ${ZMS_CLASSPATH} ${JAVA_OPTS} ${ZMS_BOOTSTRAP_CLASS} $@
}

OPTIND=1
key_dir=""
command=""
domain=""
service=""
key_id=""
zms_war=""
add_class_path=""
root=""

while getopts "h?:c:d:s:k:z:l:r:o:" opt; do
    case "$opt" in
    h|\?)
        display_usage
        exit 0
        ;;
    c)  command=$OPTARG
        ;;
    d)  domain=$OPTARG
        ;;
    s)  service=$OPTARG
        ;;
    k)  key_id=$OPTARG
        ;;
    z)  zms_war=$OPTARG
        ;;
    l)  add_class_path=$OPTARG
        ;;
    r)  root=$OPTARG
        ;;        
    o)  key_dir=$OPTARG
        generateKeys $key_dir
        ;;
    esac
done

shift $((OPTIND-1))
[ "$1" = "--" ] && shift

makeTempDir
cleanup
pub_key_name="$key_dir/public.pem"

setJavaOpts $root
executeZMSImplMain $command $domain $service $key_id $pub_key_name
ret=$?

cleanup

if [ ! $ret -eq 0 ]; then
    exit 1
fi

echo "success."
