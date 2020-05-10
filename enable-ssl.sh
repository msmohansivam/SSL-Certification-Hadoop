#!/usr/bin/env bash
#
# Enable SSL for Hadoop Web UIs
#
#TODO add support for multiple Ranger Admin hosts
#TODO automatically figure out the hostnames for each component
#TODO add ranger yarn plugin ssl
#TODO add ranger hive plugin ssl

server1="sandbox.hortonworks.com"
server2="sandbox.hortonworks.com"
server3="sandbox.hortonworks.com"

OOZIE_SERVER_ONE=$server2
NAMENODE_SERVER_ONE=$server1
RESOURCE_MANAGER_SERVER_ONE=$server3
HISTORY_SERVER=$server1
HBASE_MASTER_SERVER_ONE=$server2
RANGER_ADMIN_SERVER=$server1

ALL_NAMENODE_SERVERS="${NAMENODE_SERVER_ONE} $server2"
ALL_OOZIE_SERVERS="${OOZIE_SERVER_ONE} $server3"
ALL_HADOOP_SERVERS="$server1 $server2 $server3"
ALL_HBASE_MASTER_SERVERS="${HBASE_MASTER_SERVER_ONE} $server3"
ALL_HBASE_REGION_SERVERS="$server1 $server2 $server3"
ALL_REAL_SERVERS="$server1 $server2 $server3"
DOMAIN=$(hostname -d)

export AMBARI_SERVER=$server1
AMBARI_PASS=4o12t0n
CLUSTER_NAME=Sandbox

#
# PREP
#
mkdir -p /tmp/security
chmod -R 755 /tmp/security
cd /tmp/security
TRUST_STORE=/etc/pki/java/cacerts

#remove ssh host key checks
cat <<EOF > ~/.ssh/config
Host *
 PasswordAuthentication no
 StrictHostKeyChecking no
 ConnectTimeout 20
EOF

#generate an ssh key for passwordless ssh if this is on the sandbox
if echo $AMBARI_SERVER | grep -q -i "sandbox.hortonworks.com" ; then
    if [ ! -e ~/.ssh/id_rsa ]; then
        ssh-keygen -f ~/.ssh/id_rsa -N "" -q
    fi
    cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys
    chmod 600 ~/.ssh/authorized_keys
fi

#copy over configs.sh from Ambari server to what ever server this is
if [ ! -e "/var/lib/ambari-server/resources/scripts/configs.sh" ]; then
    mkdir -p /var/lib/ambari-server/resources/scripts/
    scp ${AMBARI_SERVER}:/var/lib/ambari-server/resources/scripts/configs.sh /var/lib/ambari-server/resources/scripts/
fi

#
# create all SSL certificates, and keys
# 1. CA SSL certificate
# 2. Server SSL certificate
# 3. Generate an SSL cert for just the domain name of the cluster
#
function generateSSLCerts() {
    rm -f /etc/pki/CA/index.txt
    touch /etc/pki/CA/index.txt
    echo '1000' > /etc/pki/CA/serial

    # 1. CA SSL certificate
    if [ ! -e "ca.crt" ]; then
        openssl genrsa -out ca.key 2048
        openssl req -new -x509 -days 1826 -key ca.key -out ca.crt -subj "/C=US/ST=New York/L=New York City/O=Hortonworks/OU=Consulting/CN=HortonworksCA"
    fi

    # 2. Server SSL certificates
    for host in ${ALL_REAL_SERVERS}; do
     if [  -e "${host}.crt" ]; then break; fi
        openssl req -new -newkey rsa:2048 -nodes -keyout ${host}.key -out ${host}.csr  -subj "/C=US/ST=New York/L=New York City/O=Hortonworks/OU=Consulting/CN=$host"
        openssl ca -batch  -startdate 20160101120000Z -cert ca.crt -keyfile ca.key -out ${host}.crt -infiles ${host}.csr
    done

    # 3. Generate an SSL cert for just the domain name of the cluster, which is needed for Oozie
    if [ ! -e "${DOMAIN}.crt" ]; then
        openssl req -new -newkey rsa:2048 -nodes -keyout ${DOMAIN}.key -out ${DOMAIN}.csr  -subj "/C=US/ST=New York/L=New York City/O=Hortonworks/OU=Consulting/CN=*.${DOMAIN}"
        openssl ca -batch  -startdate 20160101120000Z -cert ca.crt -keyfile ca.key -out ${DOMAIN}.crt -infiles ${DOMAIN}.csr
    fi

    #copy public ssl certs to all hosts
    for host in ${ALL_REAL_SERVERS}; do
        scp ca.crt ${host}:/tmp/ca.crt
        ssh $host "keytool -import -noprompt -alias myOwnCA -file /tmp/ca.crt -storepass changeit -keystore $TRUST_STORE; rm -f /tmp/ca.crt"

        for cert in ${ALL_REAL_SERVERS}; do
            scp $cert.crt ${host}:/tmp/$cert.crt
            ssh $host "keytool -import -noprompt -alias ${cert} -file /tmp/${cert}.crt -storepass changeit -keystore $TRUST_STORE; rm -f \"/tmp/${cert}.crt\""
        done
    done

    #verify certs
    for host in ${ALL_REAL_SERVERS}; do
        if [ $(openssl rsa -noout -modulus -in $host.key) != $(openssl x509 -noout -modulus -in $host.crt) ]; then
            echo $host failed verification of private key and public key pair
        else
            echo $host verified private key and public key pair
        fi
    done
}
#
# Enable Ambari SSL encryption and truststore.
#
function ambariSSLEnable() {
    rpm -q expect || yum install -y expect
    cat <<EOF > ambari-ssl-expect.exp
#!/usr/bin/expect
spawn "/usr/sbin/ambari-server" "setup-security"
expect "Enter choice"
send "1\r"
expect "Do you want to configure HTTPS"
send "y\r"
expect "SSL port"
send "\r"
expect "Enter path to Certificate"
send "/tmp/security/\$env(AMBARI_SERVER).crt\r"
expect "Enter path to Private Key"
send "/tmp/security/\$env(AMBARI_SERVER).key\r"
expect "Please enter password for Private Key"
send "\r"
send "\r"
interact
EOF

    cat <<EOF > ambari-truststore-expect.exp
#!/usr/bin/expect
spawn "/usr/sbin/ambari-server" "setup-security"
expect "Enter choice"
send "4\r"
expect "Do you want to configure a truststore"
send "y\r"
expect "TrustStore type"
send "jks\r"
expect "Path to TrustStore file"
send "/etc/pki/java/cacerts\r"
expect "Password for TrustStore"
send "changeit\r"
expect "Re-enter password"
send "changeit\r"
interact
EOF

    if ! grep -q 'api.ssl=true' /etc/ambari-server/conf/ambari.properties; then
        /usr/bin/expect ambari-ssl-expect.exp
	    /usr/bin/expect ambari-truststore-expect.exp

    	service ambari-server restart

    	while true; do if tail -100 /var/log/ambari-server/ambari-server.log | grep -q 'Started Services'; then break; else echo -n .; sleep 3; fi; done; echo
    fi

    rm -f ambari-ssl-expect.exp  ambari-truststore-expect.exp
    #validate wget -O-  --no-check-certificate "https://${AMBARI_SERVER}:8443/#/main/dashboard/metrics"
}
#
# Enable Oozie UI SSL encryption
#
function oozieSSLEnable() {
    openssl pkcs12 -export -in ${DOMAIN}.crt -inkey ${DOMAIN}.key -out oozie-server.p12 -name tomcat -CAfile ca.crt -chain -passout pass:password

    #copy and add private key to both oozie servers
    for host in ${ALL_OOZIE_SERVERS}; do
        scp oozie-server.p12 ${host}:/tmp/oozie-server.p12
        ssh $host "
            su - oozie -c \"keytool --importkeystore -noprompt -deststorepass password -destkeypass password -destkeystore ~/.keystore -srckeystore /tmp/oozie-server.p12 -srcstoretype PKCS12 -srcstorepass password -alias tomcat\";
            rm -f /tmp/oozie-server.p12;
        "
    done

    #copy the public key to all servers and add to truststore
    for host in ${ALL_REAL_SERVERS}; do
        scp ${DOMAIN}.crt ${host}:/tmp/${DOMAIN}.crt
        ssh $host "
        keytool -import -noprompt -alias tomcat -file /tmp/${DOMAIN}.crt -storepass changeit -keystore $TRUST_STORE;
        rm -f \"/tmp/${DOMAIN}.crt\";
        "
    done

    #make changes to Ambari to set oozie.base.url and add OOZIE_HTTP(S)_PORT
    /var/lib/ambari-server/resources/scripts/configs.sh -u admin -p $AMBARI_PASS -port 8443 -s set $AMBARI_SERVER $CLUSTER_NAME oozie-site oozie.base.url https://${OOZIE_SERVER_ONE}:11443/oozie &> /dev/null
    /var/lib/ambari-server/resources/scripts/configs.sh -u admin -p $AMBARI_PASS -port 8443 -s get $AMBARI_SERVER $CLUSTER_NAME oozie-env oozie-env
    perl -pe 's/(\"content\".*?)\",$/$1\\nexport OOZIE_HTTP_PORT=11000\\nexport OOZIE_HTTPS_PORT=11443\",/' -i oozie-env
     /var/lib/ambari-server/resources/scripts/configs.sh -u admin -p $AMBARI_PASS -port 8443 -s set $AMBARI_SERVER $CLUSTER_NAME oozie-env oozie-env &> /dev/null

    rm -f doSet_* oozie-env

    # Now restart Oozie

    #validate using
    # openssl s_client -connect ${OOZIE_SERVER_ONE}:11443 -showcerts  < /dev/null
    # and
    # oozie jobs -oozie  https://${OOZIE_SERVER_ONE}:11443/oozie
    #
}
#
# Enable Hadoop UIs SSL encryption. Stop all Hadoop components first
#
function hadoopSSLEnable() {

    for host in ${ALL_HADOOP_SERVERS}; do
        if [ -e "${host}.p12" ]; then continue; fi
        openssl pkcs12 -export -in ${host}.crt -inkey ${host}.key -out ${host}.p12 -name ${host} -CAfile ca.crt -chain -passout pass:password
    done

    for host in ${ALL_HADOOP_SERVERS}; do
        scp ${host}.p12 ${host}:/tmp/${host}.p12
        scp ca.crt ${host}:/tmp/ca.crt
        ssh $host "
            keytool -import -noprompt -alias myOwnCA -file /tmp/ca.crt -storepass password -keypass password -keystore /etc/hadoop/conf/hadoop-private-keystore.jks
            keytool --importkeystore -noprompt -deststorepass password -destkeypass password -destkeystore /etc/hadoop/conf/hadoop-private-keystore.jks -srckeystore /tmp/${host}.p12 -srcstoretype PKCS12 -srcstorepass password -alias ${host}

            chmod 440 /etc/hadoop/conf/hadoop-private-keystore.jks
            chown yarn:hadoop /etc/hadoop/conf/hadoop-private-keystore.jks
            rm -f /tmp/ca.crt \"/tmp/${host}.p12\";
            "
    done

    cat <<EOF | while read p; do p=${p/,}; p=${p//\"}; if [ -z "$p" ]; then continue; fi; /var/lib/ambari-server/resources/scripts/configs.sh -u admin -p $AMBARI_PASS -port 8443 -s set $AMBARI_SERVER $CLUSTER_NAME $p &> /dev/null || echo "Failed to change $p in Ambari"; done
        hdfs-site "dfs.https.enable"   "true",
        hdfs-site "dfs.http.policy"   "HTTPS_ONLY",
        hdfs-site "dfs.datanode.https.address"   "0.0.0.0:50475",
        hdfs-site "dfs.namenode.https-address"   "0.0.0.0:50470",

        core-site "hadoop.ssl.require.client.cert"   "false",
        core-site "hadoop.ssl.hostname.verifier"   "DEFAULT",
        core-site "hadoop.ssl.keystores.factory.class"   "org.apache.hadoop.security.ssl.FileBasedKeyStoresFactory",
        core-site "hadoop.ssl.server.conf"   "ssl-server.xml",
        core-site "hadoop.ssl.client.conf"   "ssl-client.xml",

        mapred-site "mapreduce.jobhistory.http.policy"   "HTTPS_ONLY",
        mapred-site "mapreduce.jobhistory.webapp.https.address"   "${HISTORY_SERVER}:19443",
        mapred-site mapreduce.jobhistory.webapp.address "${HISTORY_SERVER}:19443",

        yarn-site "yarn.http.policy"   "HTTPS_ONLY"
        yarn-site "yarn.log.server.url"   "https://${HISTORY_SERVER}:19443/jobhistory/logs",
        yarn-site "yarn.resourcemanager.webapp.https.address"   "${RESOURCE_MANAGER_SERVER_ONE}:8090",
        yarn-site "yarn.nodemanager.webapp.https.address"   "0.0.0.0:45443",

        ssl-server "ssl.server.keystore.password"   "password",
        ssl-server "ssl.server.keystore.keypassword"   "password",
        ssl-server "ssl.server.keystore.location"   "/etc/hadoop/conf/hadoop-private-keystore.jks",
        ssl-server "ssl.server.truststore.location"   "${TRUST_STORE}",
        ssl-server "ssl.server.truststore.password"   "changeit",

        ssl-client "ssl.client.keystore.location"   "${TRUST_STORE}",
        ssl-client "ssl.client.keystore.password"   "changeit",
        ssl-client "ssl.client.truststore.password"   "changeit",
        ssl-client "ssl.client.truststore.location"   "${TRUST_STORE}"
EOF
    rm -f doSet_version*
    # In Ambari, perform Start ALL

    #validate through:
}

#
# Enable HBase UI SSL encryption.  Stop all HBase services first
#
## each host gets its own SSL certificate
## some of the keyimports may fail because the HBase services run on the same hosts as the Hadoop services
function hbaseSSLEnable() {
    for host in ${ALL_HBASE_MASTER_SERVERS}; do
        if [ -e "${host}.p12" ]; then continue; fi
        openssl pkcs12 -export -in ${host}.crt -inkey ${host}.key -out ${host}.p12 -name ${host} -CAfile ca.crt -chain -passout pass:password
    done

    #copy ssl private cert to all hbase masters
    for host in ${ALL_HBASE_MASTER_SERVERS}; do
        scp ${host}.p12 ${host}:/tmp/${host}.p12
        scp ca.crt ${host}:/tmp/ca.crt
        ssh $host "
            keytool -import -noprompt -alias myOwnCA -file /tmp/ca.crt -storepass password -keypass password -keystore /etc/hadoop/conf/hadoop-private-keystore.jks
            keytool --importkeystore -noprompt -deststorepass password -destkeypass password -destkeystore /etc/hadoop/conf/hadoop-private-keystore.jks -srckeystore /tmp/${host}.p12 -srcstoretype PKCS12 -srcstorepass password -alias ${host}

            chmod 440 /etc/hadoop/conf/hadoop-private-keystore.jks
            chown yarn:hadoop /etc/hadoop/conf/hadoop-private-keystore.jks
            rm -f /tmp/ca.crt \"/tmp/${host}.p12\"
            "
    done

    /var/lib/ambari-server/resources/scripts/configs.sh -u admin -p $AMBARI_PASS -port 8443 -s set $AMBARI_SERVER $CLUSTER_NAME hbase-site "hbase.ssl.enabled" "true" &> /dev/null || echo "Failed to change hbase.ssl.enabled in Ambari"
    rm -f doSet_version*

    # In Ambari, perform Start ALL

    #validate through: openssl s_client -connect ${HBASE_MASTER_SERVER_ONE}:16010 -showcerts  < /dev/null

}

#
# Enable Ranger Admin UI SSL encryption.  Keep Ranger Admin and Ranger user-sync on the same hostname
#
function rangerAdminSSLEnable() {
    RANGER_PRIVATE_KEYSTORE=ranger-admin-keystore.jks
    openssl pkcs12  -export -in  ${RANGER_ADMIN_SERVER}.crt -inkey ${RANGER_ADMIN_SERVER}.key -out ranger-admin.p12 -name rangeradmintrust  -CAfile ca.crt -chain -passout pass:password
    keytool -import -noprompt -alias myOwnCA -file ca.crt -storepass password -keystore ${RANGER_PRIVATE_KEYSTORE}
    keytool --importkeystore -noprompt -deststorepass password -destkeypass password -destkeystore ${RANGER_PRIVATE_KEYSTORE} -srckeystore ranger-admin.p12 -srcstoretype PKCS12 -srcstorepass password -alias rangeradmintrust

    scp ${RANGER_PRIVATE_KEYSTORE} ${RANGER_ADMIN_SERVER}:/etc/ranger/admin/conf/${RANGER_PRIVATE_KEYSTORE}
    ssh ${RANGER_ADMIN_SERVER} "
        chmod 400 /etc/ranger/admin/conf/${RANGER_PRIVATE_KEYSTORE}
        chown ranger:ranger /etc/ranger/admin/conf/${RANGER_PRIVATE_KEYSTORE}
        "

    cat <<EOF | while read p; do p=${p/,}; p=${p//\"}; if [ -z "$p" ]; then continue; fi; /var/lib/ambari-server/resources/scripts/configs.sh -u admin -p $AMBARI_PASS -port 8443 -s set $AMBARI_SERVER $CLUSTER_NAME $p &>/dev/null  || echo "Failed to change $p in Ambari"; done
        ranger-admin-site ranger.https.attrib.keystore.file /etc/ranger/admin/conf/${RANGER_PRIVATE_KEYSTORE}
        ranger-admin-site  ranger.service.https.attrib.keystore.file /etc/ranger/admin/conf/${RANGER_PRIVATE_KEYSTORE}
        ranger-admin-site ranger.service.https.attrib.client.auth "false"
        ranger-admin-site ranger.service.https.attrib.keystore.pass "changeit"
        ranger-admin-site ranger.service.https.attrib.keystore.keyalias rangeradmintrust

        ranger-admin-site "ranger.service.http.enabled"   "false",
        ranger-admin-site "ranger.service.https.attrib.clientAuth"   "want",
        ranger-admin-site "ranger.service.https.attrib.keystore.pass"   "password",
        ranger-admin-site "ranger.service.https.attrib.ssl.enabled"   "true",

        ranger-ugsync-site "ranger.usersync.truststore.file" "${TRUST_STORE}",
        ranger-ugsync-site "ranger.usersync.truststore.password" "changeit",

        admin-properties "policymgr_external_url"  "https://${RANGER_ADMIN_SERVER}:6182"
EOF
    rm -f doSet_version*

    #restart Ranger via Ambari
}
#
# Ranger HDFS Plugin
#
# even though there are two NameNodes, the same SSL certificate must be used
function rangerHDFSSSLEnable() {
    RANGER_HDFS_PRIVATE_KEYSTORE=ranger-hdfs-plugin-keystore.jks

    openssl pkcs12 -export -in ${NAMENODE_SERVER_ONE}.crt -inkey ${NAMENODE_SERVER_ONE}.key -out rangerHdfsAgent.p12 -name rangerHdfsAgent -CAfile ca.crt -chain -passout pass:password

    keytool -import -noprompt -alias myOwnCA -file ca.crt -storepass password -keystore ${RANGER_HDFS_PRIVATE_KEYSTORE}
    keytool -importkeystore -noprompt -deststorepass password -destkeypass password -destkeystore ${RANGER_HDFS_PRIVATE_KEYSTORE} -srckeystore rangerHdfsAgent.p12 -srcstoretype PKCS12 -srcstorepass password -alias rangerHdfsAgent
    keytool -import -noprompt -alias rangeradmintrust -file ${RANGER_ADMIN_SERVER}.crt -storepass password -keystore ${RANGER_HDFS_PRIVATE_KEYSTORE}

    for host in ${ALL_NAMENODE_SERVERS}; do
        scp ${RANGER_HDFS_PRIVATE_KEYSTORE} ${host}:/etc/hadoop/conf/${RANGER_HDFS_PRIVATE_KEYSTORE}
        ssh ${host} "
            chown hdfs:hadoop /etc/hadoop/conf/${RANGER_HDFS_PRIVATE_KEYSTORE}
            chmod 440 /etc/hadoop/conf/${RANGER_HDFS_PRIVATE_KEYSTORE}
            "
    done

    cat <<EOF | while read p; do p=${p/,}; p=${p//\"}; if [ -z "$p" ]; then continue; fi; /var/lib/ambari-server/resources/scripts/configs.sh -u admin -p $AMBARI_PASS -port 8443 -s set $AMBARI_SERVER $CLUSTER_NAME $p &> /dev/null || echo "Failed to change $p in Ambari"; done

        ranger-hdfs-policymgr-ssl "xasecure.policymgr.clientssl.keystore"   /etc/hadoop/conf/${RANGER_HDFS_PRIVATE_KEYSTORE},
        ranger-hdfs-policymgr-ssl "xasecure.policymgr.clientssl.keystore.password"   "password",
        ranger-hdfs-policymgr-ssl "xasecure.policymgr.clientssl.truststore"  "${TRUST_STORE}",
        ranger-hdfs-policymgr-ssl "xasecure.policymgr.clientssl.truststore.password"   "changeit"
EOF
    rm -f doSet_version*
    #add to Ranger Admin UI
    #restart HDFS

    #[root@node1 security]# cat node1.vzlatkin.com.key node1.vzlatkin.com.crt  >> node1.vzlatkin.com.pem
    # [root@node1 security]# curl --cacert /tmp/security/ca.crt --cert /tmp/security/node1.vzlatkin.com.pem "https://node1.vzlatkin.com:6182/service/plugins/policies/download/cluster1_hadoop?lastKnownVersion=3&pluginId=hdfs@node1.vzlatkin.com-cluster1_hadoop"

    # look for "util.PolicyRefresher" in logs
}
#
# Ranger HBase Plugin
#
function rangerHBaseSSLEnable() {
    RANGER_HBASE_PRIVATE_KEYSTORE=ranger-hbase-plugin-keystore.jks

    openssl pkcs12 -export -in ${HBASE_MASTER_SERVER_ONE}.crt -inkey ${HBASE_MASTER_SERVER_ONE}.key -out rangerHbaseAgent.p12 -name rangerHbaseAgent -CAfile ca.crt -chain -passout pass:password

    keytool -importkeystore -noprompt -deststorepass password -destkeypass password -destkeystore ${RANGER_HBASE_PRIVATE_KEYSTORE}  -srckeystore rangerHbaseAgent.p12 -srcstoretype PKCS12 -srcstorepass password -alias rangerHbaseAgent
    keytool -import -noprompt -alias rangeradmintrust -file ${RANGER_ADMIN_SERVER}.crt -storepass password -keystore ${RANGER_HBASE_PRIVATE_KEYSTORE}
    keytool -import -noprompt -alias myOwnCA -file ca.crt -storepass password -keystore ${RANGER_HBASE_PRIVATE_KEYSTORE}

    for host in ${ALL_HBASE_MASTER_SERVERS} ${ALL_HBASE_REGION_SERVERS}; do
        scp ${RANGER_HBASE_PRIVATE_KEYSTORE} ${host}:/etc/hadoop/conf/${RANGER_HBASE_PRIVATE_KEYSTORE}
        ssh ${host} "
            chown hbase:hadoop /etc/hadoop/conf/${RANGER_HBASE_PRIVATE_KEYSTORE}
            chmod 440 /etc/hadoop/conf/${RANGER_HBASE_PRIVATE_KEYSTORE}
            "
    done

    cat <<EOF | while read p; do p=${p/,}; p=${p//\"}; if [ -z "$p" ]; then continue; fi; /var/lib/ambari-server/resources/scripts/configs.sh -u admin -p $AMBARI_PASS -port 8443 -s set $AMBARI_SERVER $CLUSTER_NAME $p &> /dev/null || echo "Failed to change $p in Ambari"; done
        ranger-hbase-policymgr-ssl "xasecure.policymgr.clientssl.keystore"  /etc/hadoop/conf/${RANGER_HBASE_PRIVATE_KEYSTORE},
        ranger-hbase-policymgr-ssl "xasecure.policymgr.clientssl.keystore.password"  "password"
        ranger-hbase-policymgr-ssl "xasecure.policymgr.clientssl.truststore" "${TRUST_STORE}",
        ranger-hbase-policymgr-ssl "xasecure.policymgr.clientssl.truststore.password"  "changeit"
EOF
    rm -f doSet_version*
    #add CN via Ranger Admin UI
    #restart HBase via Ambari

    #validate via
    # [root@node1 security]#  cat node2.vzlatkin.com.key node2.vzlatkin.com.crt  >> node2.vzlatkin.com.pem
    #[root@node1 security]# curl --cacert /tmp/security/ca.crt --cert /tmp/security/node2.vzlatkin.com.pem "https://node1.vzlatkin.com:6182/service/plugins/policies/download/cluster1_hbase?lastKnownVersion=3&pluginId=hbase@node2.vzlatkin.com-cluster1_hbase"
}

function usage() {
    echo "Usage: $0 [--all] [--hbaseSSL] [--oozieSSL] [--hadoopSSL] [ --rangerSSL] [--ambariSSL]"
    exit 1
}

if [ "$#" -lt 1 ]; then
    usage
fi

while [ "$#" -ge 1 ]; do
    key="$1"

    case $key in
        --all)
            generateSSLCerts
            ambariSSLEnable
            oozieSSLEnable
            hadoopSSLEnable
            hbaseSSLEnable
            rangerAdminSSLEnable
            rangerHDFSSSLEnable
            rangerHBaseSSLEnable
        ;;
        --hbaseSSL)
            generateSSLCerts
            ambariSSLEnable
            hadoopSSLEnable
            hbaseSSLEnable
        ;;
        --oozieSSL)
            generateSSLCerts
            ambariSSLEnable
            oozieSSLEnable
        ;;
        --hadoopSSL)
            generateSSLCerts
            ambariSSLEnable
            hadoopSSLEnable
        ;;
        --rangerSSL)
            generateSSLCerts
            ambariSSLEnable
            rangerAdminSSLEnable
            rangerHDFSSSLEnable
            rangerHBaseSSLEnable
        ;;
        --ambariSSL)
            generateSSLCerts
            ambariSSLEnable
        ;;
        *)
            usage
        ;;
    esac
    shift
done