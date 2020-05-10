# SSL Certification Process for Hadoop Cluster
 
* Summary

  1. For client interaction, Authentication, and service level authorization  can be achieved by using  with Kerberos . The data transferred between hadoop services and clients can be encrypted by setting hadoop.rpc.protection to “privacy” in the core-site.xml.
  
  2. Data transfer between Web-consoles and client can be secured by implementing SSL/TLS (HTTPS).
  3. And finally the data communications between data nodes can be secured using encryption methods. Need to set dfs.encrypt.data.transfer to “true” in the hdfs-site.xml in order to activate data encryption for data transfer protocol of DataNode. If dfs.encrypt.data.transfer is set to true, then it supersedes the setting for dfs.data.transfer.protection and enforces that all connections must use a specialized encrypted SASL handshake.
  
This article aims to simplify the process by presenting a semi-automated, start-to-finish example that enables SSL for the below Web UIs in the Hortonworks Sandbox:

  * Ambari 
  * HBase
  
  * Oozie
  
  * Ranger
  
  * HDFS

# Planning

  If we are planing to enable SSL in a production cluster, then make sure we are familiar with SSL concepts and the communication paths between each HDP component. In addition, plan on cluster downtime. Here are some concepts that you should know well:

   1. Certificate Authority (CA)

  In cryptography, a certificate authority or certification authority (CA) is an entity that issues digital certificates. A digital certificate certifies the ownership of a public key by the named subject of the certificate. This allows others (relying parties) to rely upon signatures or on assertions made about the private key that corresponds to the certified public key. A CA acts as a trusted third party—trusted both by the subject (owner) of the certificate and by the party relying upon the certificate.

  2. Server SSL certificate

  SSL Certificates are small data files that digitally bind a cryptographic key to an organization’s details. When installed on a web server, it activates the padlock and the https protocol and allows secure connections from a web server to a browser. Typically, SSL is used to secure credit card transactions, data transfer and logins, and more recently is becoming the norm when securing browsing of social media sites.

  3. Java private keystore

  A Java KeyStore (JKS) is a repository of security certificates – either authorization certificates or public key certificates – plus corresponding private keys, used for instance in SSL encryption. In IBM WebSphere Application Server and Oracle WebLogic Server, a file with extension jks serves as a keystore.
  When Java HDP services need to encrypt messages, they need a place to look for the private key part of a server's SSL certificate. This keystore holds those private keys. It should be kept secure so that attackers cannot impersonate the service. For this reason, each HDP component in this article has its own private keystore.
  http://tutorials.jenkov.com/java-cryptography/keystore.html
  
  4. Java trust keystore

  Just like my Mac has a list of CAs that it trusts, a Java process on a Linux machine needs the same. This keystore will usually hold the Public CA's certificate and any intermediary CA certificates. If a certificate was signed with a CA that you created yourself then also add the public part of a server's SSL certificate into this keystore.
  
  5. Ranger plugins

  Ranger plugins communicate with Ranger Admin server over SSL. What is important to understand is where each plugin executes and thus where server SSL certificates are needed. For HDFS, the execution is on the NameNodes, for HBase, it is on the RegionServers, for YARN, it is on the ResourceManagers. When you create server SSL certificates use the hostnames where the plugins execute.
  *************************************************************************************************************************
  
 # Enable SSL on HDP Sandbox

  Install the HDP 2.4 Sandbox and follow the below steps. If you use an older version of the Sandbox note that you'll need to change the Ambari password used in the script.

    1. Download the script enable.ssh
	
    2. Stop all services via Ambari (manually stop HDFS or Turn Off Maintenance Mode)
    3. Execute:
        /bin/bash enable-ssl.sh --all
	
    4. Start all services via Ambari, which is now running on port 8443
    5. Goto Ranger Admin UI and edit HDFS and HBase services to set the Common Name for Certificate to sandbox.hortonworks.com
    
# Enable SSL in production

There are two big reasons why enabling SSL in production can be more difficult than in a sandbox:

    1. If Hadoop components run in Highly Available mode. The solution for most instances is to create a single server SSL certificate and copy it to all HA servers. However, for Oozie you'll need a special server SSL certificate with CN=*.domainname.com
    
    2. If using Public CAs to sign server SSL certificates. Besides adding time to the process that is needed for the CA to sign your certificates you may also need additional steps to add intermediate CA certificates to the various Java trust stores and finding a CA that can sign non-FQDN server SSL certificates for Oozie HA
    
If you are using Ranger to secure anything besides HBase and HDFS then you will need to make changes to the script to enable extra plugins. The steps are similar to enabling SSL in Sanbox:

    1. Download the script enable-ssl.sh
	
    2. Make changes to these variables inside of the script to reflect your cluster layout. The script uses these variables to generate        certificates and copy them to all machines where they are needed. Below is an example for my three node cluster.
              server1="cm.com"
              server2="worker1.com"
              server3="worker2.com"
              OOZIE_SERVER_ONE=$server2
              NAMENODE_SERVER_ONE=$server1
              RESOURCE_MANAGER_SERVER_ONE=$server3
              HISTORY_SERVER=$server1
              HBASE_MASTER_SERVER_ONE=$server2
              RANGER_ADMIN_SERVER=$server1
              ALL_NAMENODE_SERVERS="${NAMENODE_SERVER_ONE} $server2"
              ALL_OOZIE_SERVERS="${OOZIE_SERVER_ONE} $server3"
              ALL_HBASE_MASTER_SERVERS="${HBASE_MASTER_SERVER_ONE} $server3"
              ALL_HBASE_REGION_SERVERS="$server1 $server2 $server3"
              ALL_REAL_SERVERS="$server1 $server2 $server3"
              ALL_HADOOP_SERVERS="$server1 $server2 $server3"
              export AMBARI_SERVER=$server1
              AMBARI_PASS=P@ssw0rd
              CLUSTER_NAME=mohandemo
	
    3. If you are going to pay a Public CA to sign your server SSL certificates then copy them to /tmp/security and name them as such:
              ca.crt
              cm.com.crt
              cm.com.key
              worker1.com.crt
              worker1.com.key
              worker2.com.crt
              worker2.key
              hortonworks.com.crt
              hortonworks.com.key
	
    The last certificate is needed for Oozie if you have Oozie HA enabled. The CN of that certificate should be CN=*.domainname.com as       described hereIf you are NOT going to use a Public CA to sign your certificates, then change these lines in the script to be             relevant to your organization:
    
      /C=US/ST=New York/L=New York City/O=Hortonworks/OU=Consulting/CN=HortonworksCA
	
    4. Stop all services via Ambari
    5. Execute:
        /bin/bash enable-ssl.sh --all
	
    6. Start all services via Ambari, which is now running on port 8443
    7. Goto Ranger Admin UI and edit HDFS and HBase services to set the Common Name for Certificate to $NAMENODE_SERVER_ONE and                $HBASE_MASTER_SERVER_ONE that you specified in the above script
    
If you chose not to enable SSL for some components or decide to modify the script to include others (please send me a patch) then be aware of these dependencies:

    * Setting up Ambari trust store is required before enabling SSL encryption for any other component
    * Before you enable HBase SSL encryption, enable Hadoop SSL encryption

* Validation tips

      1. View and verify SSL certificate being used by a server
          openssl s_client -connect ${OOZIE_SERVER_ONE}:11443 -showcerts  < /dev/null
	
      2. View Oozie jobs through command-line
          oozie jobs -oozie  https://${OOZIE_SERVER_ONE}:11443/oozie
	
      3. View certificates stored in a Java keystore
          keytool -list -storepass password -keystore /etc/hadoop/conf/hadoop-private-keystore.jks
	
      4. View Ranger policies for HDFS
          cat cm.com.key cm.com.crt  >> cm.com.pem
          curl --cacert /tmp/security/ca.crt --cert /tmp/security/cm.com.pem                  "https://cm.com:6182/service/plugins/policies/download/mohandemo_hadoop?lastKnownVersion=3&pluginId=hdfs@cm.com-mohandemo_hadoop"
	
      5. Validate that Ranger plugins can connect to Ranger admin server by searching for util.PolicyRefresher in HDFS NameNode and    HBase RegionServer log files
      
* References

  * https://docs.cloudera.com/HDPDocuments/HDP2/HDP-2.4.0/bk_Security_Guide/content/set_up_ssl_for_ambari.html
  * https://docs.cloudera.com/HDPDocuments/HDP2/HDP-2.4.0/bk_Security_Guide/content/ch_wire-webhdfs-mr-yarn.html
  * http://bdlabs.edureka.co/static/help/topics/cm_sg_ssl_yarn_mr_hdfs.html
  

