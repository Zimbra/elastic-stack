# Zimbra Elastic Stack

This guide describes how to use Elastic Stack with Zimbra by using Centralized Logging based on RSyslog. The main benefits of using Elastic Stack combined with Centralized Logging:
 
* Makes it easy to search through and analyze historic logs.
* Visualization of log events to gather insights.
* Storing of logs for forensic research in case of getting hacked.
* Uptime and certificate monitoring.

Both Zimbra and Elastic Stack consist of many components. The below diagram gives an overview of how the software components work together to make visualizations from raw log files. In the most simple form you can install Zimbra in a single server set-up and add another server for all the Elastic Stack components. Of course, if you plan to scale up you may split several of the software components across more virtual machines as required.

![](screenshots/zimbra-logstack.dia.png)
*Example of a Zimbra Cluster with Elastic Stack and RSyslog.*

A basic Kibana dashboard for a Zimbra server would look like this:

![](screenshots/01-dashboard.png)
*Example Elastic Stack Dashboard on a Zimbra 9 installation.*

Without Elastic Stack your server only keeps the most recent log files of all the events happening on your Zimbra server. Even though you can configure your system logging to delay the compression and purging of log files, eventually log files tend to become very large and there are several log files for the various components in the system. Finding a specific event across all these logs can be time consuming.

Logs that are parsed by Elastic Stack become searchable, so you don't have to do all sorts of command line tricks to search for events quickly and go back in time without spending extended periods of time waiting for search results.

In addition to the search, Elastic Stack allows you to create visualizations in a relatively easy way. This way you can get insights into the vital parameters of your system, including but not limited to Postfix e-mail traffic, spam filtering, disk usage and load, CPU and RAM usage, and security related events such as failed web-UI log-ins, failed SSH login attempts, IMAP and SMTP brute force attempts etc. In time this can help you to become proactive in dealing with system load issues and security threats.

Using RSyslog to gather the logs of your Zimbra servers has a number of benefits over using Elastic stack mechanisms to gather logs:

* No need to install Elastic Stack agent on your Zimbra servers.
* Avoid 3rd party software repositories on your Zimbra servers.
* RSyslog centralized logging will secure your logs in case your server logs become compromised because of hacking.
* RSyslog centralized logging is an industry standard for securing logs for forensic researchers.
* Maintainability.

With regards to maintainability, Elastic Stack is DevOps developed software. While there is nothing wrong with that, over time things tends to change a lot. This means the mechanisms (Logstash Forwarder/Filebeat) offered for gathering logs can change significantly. For example Logstash Forwarder is now deprecated and the configuration options for Filebeat change often, making it challenging to maintain, especially if you run a Zimbra cluster. 

Please note that most of the config files and scripts that are in this guide are available in the Github repository. So if copy-pasting directly from this guide  does not work, you should retrieve the config files and scripts by downloading them via Github.

## Hardware and Software considerations

You will need one additional virtual machine that will serve as the RSyslog logging server and the Elastic Stack server. You can optionally split the two but this is not really needed and not described in this guide. You will have to pick an operating system that is both supported by RSyslog and Elastic Stack. The instructions in this guide are for setting up Elastic on Ubuntu 22.04 LTS and Zimbra 9 or 10 on Ubuntu 20.04 LTS. Details for Elastic system:

- OS: Ubuntu 22.04 LTS
- RAM: 8GB
- CPU: 4
- Disk: 100GB (SSD preferred)

Please note that the logging tends to consume a large amount of disk space, so even though you can start from a smaller disk you need a solution that allows you to grow your disk over time, you can also archive your entire Elastic Stack periodically and revert to an clean snapshot on a yearly basis.

## Installing the Centralized Log Server

On the Ubuntu 22 server where we will install the Central Logging server and Elastic Stack, make sure to install all updates by running:

      apt update && apt upgrade
      reboot

In this guide we will set-up the RSyslog server to force the use of TLS so that our logs are transmitted over an encrypted connection. In case you are running your servers on an isolated network, you can opt to skip the TLS configuration. Please be advised that in case you first use RSyslog without TLS and then add it later, Zimbra/mailboxd does not recognize it. You will need to restart Zimbra to make it resume communications with RSyslog. If you do not restart Zimbra you will lose mailbox logs.

### Server/client terminology

In the paragraphs that describe RSyslog installation the term _server_ is used to designate the RSyslog server. In other words the RSyslog server is what receives logs. The term _client_ is used for the server that is sending the logs to RSyslog. So the Zimbra server is an RSyslog _client_.

### Install the necessary packages

      apt install -y rsyslog rsyslog-gnutls gnutls-bin haveged

### Create the TLS certificates for RSyslog server and client

You will notice the use of the same name for the client and server, you can use different names to create a more secure set-up.

      mkdir  /etc/rsyslog-certs
      cd /etc/rsyslog-certs
      
      certtool --generate-privkey --outfile ca-key.pem
         Generating a 3072 bit RSA private key...

      certtool --generate-self-signed --load-privkey ca-key.pem --outfile ca.pem
         Generating a self signed certificate...
         Please enter the details of the certificate's distinguished name. Just press enter to ignore a field.
         Common name: elastic.barrydegraaff.nl
         UID: 
         Organizational unit name: 
         Organization name: 
         Locality name: 
         State or province name: 
         Country name (2 chars): 
         Enter the subject's domain component (DC): 
         This field should not be used in new certificates.
         E-mail: 
         Enter the certificate's serial number in decimal (123) or hex (0xabcd)
         (default is 0x5bf740ed0e28daae2913f2fe8d1eabd00b58cb16)
         value: 
         
         Activation/Expiration time.
         The certificate will expire in (days): 3650
         
         Extensions.
         Does the certificate belong to an authority? (y/N): y
         Path length constraint (decimal, -1 for no constraint): 
         Is this a TLS web client certificate? (y/N): 
         Will the certificate be used for IPsec IKE operations? (y/N): 
         Is this a TLS web server certificate? (y/N): 
         Enter a dnsName of the subject of the certificate: 
         Enter a URI of the subject of the certificate: 
         Enter the IP address of the subject of the certificate: 
         Enter the e-mail of the subject of the certificate: 
         Will the certificate be used for signing (required for TLS)? (Y/n):  
         Will the certificate be used for data encryption? (y/N): 
         Will the certificate be used to sign OCSP requests? (y/N): 
         Will the certificate be used to sign code? (y/N): 
         Will the certificate be used for time stamping? (y/N): 
         Will the certificate be used for email protection? (y/N): 
         Will the certificate be used to sign other certificates? (Y/n):  
         Will the certificate be used to sign CRLs? (y/N): 
         Enter the URI of the CRL distribution point: 
         X.509 Certificate Information:
            Version: 3
            Serial Number (hex): 5bf740ed0e28daae2913f2fe8d1eabd00b58cb16
            Validity:
               Not Before: Mon Apr 12 08:12:54 UTC 2021
               Not After: Thu Apr 10 08:13:02 UTC 2031
            Subject: CN=elastic.barrydegraaff.nl
            Subject Public Key Algorithm: RSA
            Algorithm Security Level: High (3072 bits)
               Modulus (bits 3072):
                  00:ce:a1:a8:ca:b0:88:aa:aa:f3:95:f9:bc:3d:39:0d
                  42:ee:f2:5c:7a:bc:af:28:16:3f:0b:3e:3e:2e:f1:b0
                  f3:60:5c:ca:1c:da:22:6e:69:05:8b:e7:a4:33:73:cd
                  26:36:3f:ca:91:9c:9d:5b:f7:fa:5c:b5:87:12:ad:29
                  31:e9:be:5e:32:76:64:7b:88:8e:30:77:0b:81:6f:93
                  71:ea:2e:4a:e0:11:d0:ce:96:88:b1:0a:3a:ec:dc:d3
                  d1:b3:70:9a:55:be:5b:22:4d:d1:53:74:85:54:3f:84
                  15:9f:0c:a3:78:ac:ce:0f:e1:18:53:11:ed:49:dc:65
                  91:af:3a:9d:73:b9:50:5c:7e:4c:61:bd:c9:59:c0:31
                  59:72:70:0e:20:e6:cb:cf:75:de:32:51:47:66:b3:23
                  36:cc:2b:59:1d:8e:92:81:fb:18:b1:da:1e:b8:30:5c
                  41:04:d5:dc:c9:a9:79:4f:c4:05:5b:45:f6:5f:46:3d
                  44:1e:79:97:a4:bd:3f:d3:e7:18:f0:aa:89:5e:2c:43
                  1e:28:ef:f1:2f:7f:39:36:5e:da:1a:e4:52:54:6f:84
                  d2:92:e8:af:ea:b4:51:37:04:95:67:07:49:63:62:8c
                  8a:b9:c9:9a:54:46:32:d3:21:e8:2f:dd:03:88:d5:55
                  e0:ae:98:4a:48:c1:11:d0:7c:4a:96:be:b1:2d:ac:e6
                  0f:96:05:67:41:d7:d3:34:c9:ba:46:12:50:a6:02:4e
                  2a:64:21:7e:ae:ac:37:72:3e:18:0f:8d:2f:f3:ab:d4
                  ec:98:8e:b5:6f:ee:21:95:d1:9a:5b:bb:eb:a9:47:eb
                  74:b7:5e:9e:98:7f:7c:ac:eb:37:bb:fd:cf:bf:4a:b6
                  e1:f1:60:37:08:c7:3c:71:f0:6d:13:db:d1:f8:ba:ec
                  4a:1f:9c:c6:6d:92:02:26:ae:e2:f8:93:3f:87:9c:c1
                  0f:ad:ac:82:7d:8f:60:7f:99:ff:2d:6a:a6:de:39:11
                  2f
               Exponent (bits 24):
                  01:00:01
            Extensions:
               Basic Constraints (critical):
                  Certificate Authority (CA): TRUE
               Key Usage (critical):
                  Digital signature.
                  Certificate signing.
               Subject Key Identifier (not critical):
                  87ad4c435065629d69725be0198370ed013880a1
         Other Information:
            Public Key ID:
               sha1:87ad4c435065629d69725be0198370ed013880a1
               sha256:84cd614abfed8d7247ec47bac7561dc4e7aa40ad181a0d9f564d4560122b8313
            Public Key PIN:
               pin-sha256:hM1hSr/tjXJH7Ee6x1YdxOeqQK0YGg2fVk1FYBIrgxM=
         
         Is the above information ok? (y/N): y
         
         Signing certificate...

      certtool --generate-privkey --outfile rslclient-key.pem --bits 2048
         ** Note: You may use '--sec-param Medium' instead of '--bits 2048'
         Generating a 2048 bit RSA private key..

      certtool --generate-request --load-privkey rslclient-key.pem --outfile request.pem
         Generating a PKCS #10 certificate request...
         Common name: elastic.barrydegraaff.nl
         Organizational unit name: 
         Organization name: 
         Locality name: 
         State or province name: 
         Country name (2 chars): 
         Enter the subject's domain component (DC): 
         UID: 
         Enter a dnsName of the subject of the certificate: elastic.barrydegraaff.nl
         Enter an additional dnsName of the subject of the certificate: 
         Enter a URI of the subject of the certificate: 
         Enter the IP address of the subject of the certificate: 
         Enter the e-mail of the subject of the certificate: 
         Enter a challenge password: 
         Does the certificate belong to an authority? (y/N): 
         Will the certificate be used for signing (DHE ciphersuites)? (Y/n): 
         Will the certificate be used for encryption (RSA ciphersuites)? (Y/n): 
         Will the certificate be used to sign code? (y/N): 
         Will the certificate be used for time stamping? (y/N): 
         Will the certificate be used for email protection? (y/N): 
         Will the certificate be used for IPsec IKE operations? (y/N): 
         Will the certificate be used to sign OCSP requests? (y/N): 
         Is this a TLS web client certificate? (y/N): y
         Is this a TLS web server certificate? (y/N): y
      
      certtool --generate-certificate --load-request request.pem --outfile rslclient-cert.pem --load-ca-certificate ca.pem --load-ca-privkey ca-key.pem
         Generating a signed certificate...
         Enter the certificate's serial number in decimal (123) or hex (0xabcd)
         (default is 0x387d307625919e759413cbf38ab981f1bdbd8976)
         value: 
         
         Activation/Expiration time.
         The certificate will expire in (days): 3649
         
         Extensions.
         Do you want to honour all the extensions from the request? (y/N): 
         Does the certificate belong to an authority? (y/N): 
         Is this a TLS web client certificate? (y/N): y
         Will the certificate be used for IPsec IKE operations? (y/N): 
         Is this a TLS web server certificate? (y/N): y
         Enter a dnsName of the subject of the certificate: elastic.barrydegraaff.nl
         Enter an additional dnsName of the subject of the certificate: 
         Enter a URI of the subject of the certificate: 
         Enter the IP address of the subject of the certificate: 
         Will the certificate be used for signing (DHE ciphersuites)? (Y/n): 
         Will the certificate be used for encryption (RSA ciphersuites)? (Y/n): 
         Will the certificate be used for data encryption? (y/N): 
         Will the certificate be used to sign OCSP requests? (y/N): 
         Will the certificate be used to sign code? (y/N): 
         Will the certificate be used for time stamping? (y/N): 
         Will the certificate be used for email protection? (y/N): 
         X.509 Certificate Information:
            Version: 3
            Serial Number (hex): 387d307625919e759413cbf38ab981f1bdbd8976
            Validity:
               Not Before: Mon Apr 12 08:22:12 UTC 2021
               Not After: Wed Apr 09 08:22:16 UTC 2031
            Subject: CN=elastic.barrydegraaff.nl
            Subject Public Key Algorithm: RSA
            Algorithm Security Level: Medium (2048 bits)
               Modulus (bits 2048):
                  00:c5:52:2f:e6:2a:d1:41:b3:03:4d:0c:b2:79:46:31
                  d9:56:ae:93:48:d1:b0:d9:d5:8a:61:63:96:c6:ac:73
                  d6:da:31:75:e4:3f:05:2d:7d:4f:ae:1e:2d:57:21:ea
                  1d:0b:86:28:0f:cd:97:c3:75:48:3b:34:38:8b:fa:b6
                  da:ee:3a:bb:03:65:bb:a5:27:8f:eb:f0:4f:a7:97:0a
                  cf:12:79:95:af:a6:94:78:13:03:9e:09:6e:df:76:25
                  f1:ac:b7:af:79:9f:28:75:90:1b:a9:b2:6b:6e:35:6f
                  db:b3:10:8c:d8:7d:63:c4:4a:f3:53:15:47:8a:33:6a
                  52:08:8b:04:5d:d4:ca:da:bc:e1:bc:16:ef:0c:02:37
                  6c:cb:5e:42:5d:23:79:a4:fc:a1:ae:81:71:51:23:fa
                  b0:db:be:16:8e:88:10:84:0e:d7:65:3d:c0:8b:41:db
                  ad:dc:c6:9b:46:94:5d:b5:75:8d:bb:fa:9b:a7:60:81
                  d8:9b:2d:6a:99:4c:fc:3d:94:e2:1b:b8:e3:f8:01:e1
                  bc:7e:72:95:6c:b2:0d:ef:aa:12:8e:10:54:02:d9:34
                  aa:da:26:cf:01:28:4e:bb:50:93:b4:9b:f4:b9:fb:e1
                  98:e1:d3:6c:ab:a1:c4:99:51:17:a8:ec:16:80:d3:87
                  3f
               Exponent (bits 24):
                  01:00:01
            Extensions:
               Basic Constraints (critical):
                  Certificate Authority (CA): FALSE
               Key Purpose (not critical):
                  TLS WWW Client.
                  TLS WWW Server.
               Subject Alternative Name (not critical):
                  DNSname: elastic.barrydegraaff.nl
               Key Usage (critical):
                  Digital signature.
                  Key encipherment.
               Subject Key Identifier (not critical):
                  2bbb7eb737ae9b38a6ef9479dc0f0141a2a433b9
               Authority Key Identifier (not critical):
                  87ad4c435065629d69725be0198370ed013880a1
         Other Information:
            Public Key ID:
               sha1:2bbb7eb737ae9b38a6ef9479dc0f0141a2a433b9
               sha256:089807418b99185dbf36bfee7bdcd79ddb8e46f1f6e36db0d5abb44f38788ee6
            Public Key PIN:
               pin-sha256:CJgHQYuZGF2/Nr/ue9zXnduORvH2422w1au0Tzh4juY=
         
         Is the above information ok? (y/N): y
         
         Signing certificate...
      
      certtool --generate-privkey --outfile rslserver-key.pem --bits 2048
         ** Note: You may use '--sec-param Medium' instead of '--bits 2048'
         Generating a 2048 bit RSA private key...

      certtool --generate-request --load-privkey rslserver-key.pem --outfile request.pem
         Generating a PKCS #10 certificate request...
         Common name: elastic.barrydegraaff.nl
         Organizational unit name: 
         Organization name: 
         Locality name: 
         State or province name: 
         Country name (2 chars): 
         Enter the subject's domain component (DC): 
         UID: 
         Enter a dnsName of the subject of the certificate: elastic.barrydegraaff.nl
         Enter an additional dnsName of the subject of the certificate: 
         Enter a URI of the subject of the certificate: 
         Enter the IP address of the subject of the certificate: 
         Enter the e-mail of the subject of the certificate: 
         Enter a challenge password: 
         Does the certificate belong to an authority? (y/N): 
         Will the certificate be used for signing (DHE ciphersuites)? (Y/n): 
         Will the certificate be used for encryption (RSA ciphersuites)? (Y/n): 
         Will the certificate be used to sign code? (y/N): 
         Will the certificate be used for time stamping? (y/N): 
         Will the certificate be used for email protection? (y/N): 
         Will the certificate be used for IPsec IKE operations? (y/N): 
         Will the certificate be used to sign OCSP requests? (y/N): 
         Is this a TLS web client certificate? (y/N): y
         Is this a TLS web server certificate? (y/N): y
      
      certtool --generate-certificate --load-request request.pem --outfile rslserver-cert.pem --load-ca-certificate ca.pem --load-ca-privkey ca-key.pem
         Generating a signed certificate...
         Enter the certificate's serial number in decimal (123) or hex (0xabcd)
         (default is 0x00f9b2bbc95cdcc99b4d65ee208380b867ee4232)
         value: 
         
         Activation/Expiration time.
         The certificate will expire in (days): 3649
         
         Extensions.
         Do you want to honour all the extensions from the request? (y/N): 
         Does the certificate belong to an authority? (y/N): 
         Is this a TLS web client certificate? (y/N): y
         Will the certificate be used for IPsec IKE operations? (y/N): 
         Is this a TLS web server certificate? (y/N): y
         Enter a dnsName of the subject of the certificate: elastic.barrydegraaff.nl
         Enter an additional dnsName of the subject of the certificate: 
         Enter a URI of the subject of the certificate: 
         Enter the IP address of the subject of the certificate: 
         Will the certificate be used for signing (DHE ciphersuites)? (Y/n): 
         Will the certificate be used for encryption (RSA ciphersuites)? (Y/n): 
         Will the certificate be used for data encryption? (y/N): 
         Will the certificate be used to sign OCSP requests? (y/N): 
         Will the certificate be used to sign code? (y/N): 
         Will the certificate be used for time stamping? (y/N): 
         Will the certificate be used for email protection? (y/N): 
         X.509 Certificate Information:
            Version: 3
            Serial Number (hex): 00f9b2bbc95cdcc99b4d65ee208380b867ee4232
            Validity:
               Not Before: Mon Apr 12 08:27:11 UTC 2021
               Not After: Wed Apr 09 08:27:19 UTC 2031
            Subject: CN=elastic.barrydegraaff.nl
            Subject Public Key Algorithm: RSA
            Algorithm Security Level: Medium (2048 bits)
               Modulus (bits 2048):
                  00:b4:93:e0:52:c2:5c:39:0e:2b:ba:5f:b7:84:e4:29
                  c1:0c:f4:cc:2c:c6:2b:3d:e4:3f:15:d7:44:7d:5b:55
                  dd:9e:83:cf:44:68:e5:ab:c1:ab:06:41:86:2c:23:93
                  0d:57:74:fc:cc:06:77:89:0c:b6:83:3d:3e:d4:08:41
                  d5:a2:3d:b4:15:3f:e5:3b:05:66:3e:df:b2:8c:67:00
                  4b:ac:86:a2:ea:c6:55:b6:a1:a2:6b:da:22:18:80:10
                  c8:16:a7:4f:29:bb:96:8d:55:41:33:6f:5b:07:4a:79
                  43:8c:ee:93:21:98:30:6e:25:76:54:e2:b0:02:4b:94
                  bb:e2:5f:9b:00:13:51:7b:54:42:aa:76:63:47:11:c5
                  83:19:84:cf:ed:60:70:b2:c5:e1:44:7e:04:e1:ce:48
                  d0:48:e1:c3:88:48:33:30:d7:d2:ea:9d:b7:15:60:e5
                  f5:ae:43:0b:a2:b8:c7:ed:ba:6f:5a:2f:70:ce:0a:db
                  c8:83:ec:d3:87:37:4b:0e:48:62:35:75:68:cf:43:03
                  20:b5:6d:a9:1a:9a:ec:7a:c4:3f:bf:7d:b4:e1:2b:d1
                  f5:90:f8:94:76:d2:6f:11:a2:0f:49:cc:f1:9f:0d:48
                  0b:42:e1:60:c0:fd:d8:07:6e:65:98:14:28:60:39:6b
                  e9
               Exponent (bits 24):
                  01:00:01
            Extensions:
               Basic Constraints (critical):
                  Certificate Authority (CA): FALSE
               Key Purpose (not critical):
                  TLS WWW Client.
                  TLS WWW Server.
               Subject Alternative Name (not critical):
                  DNSname: elastic.barrydegraaff.nl
               Key Usage (critical):
                  Digital signature.
                  Key encipherment.
               Subject Key Identifier (not critical):
                  f3e57c60fc4bb5aa52bb643a0cc79ffa4143967a
               Authority Key Identifier (not critical):
                  87ad4c435065629d69725be0198370ed013880a1
         Other Information:
            Public Key ID:
               sha1:f3e57c60fc4bb5aa52bb643a0cc79ffa4143967a
               sha256:2fe65cb6504389fa5d890014f70d655d6d51e6607f1e23778fccda5b26cf1661
            Public Key PIN:
               pin-sha256:L+ZctlBDifpdiQAU9w1lXW1R5mB/HiN3j8zaWybPFmE=
         
         Is the above information ok? (y/N): y
         
         Signing certificate...

```
chown syslog:syslog /etc/rsyslog-certs -R
```

Finally it should look like this:

      ls -hal /etc/rsyslog-certs
         total 56K
         drwxr-xr-x  2 syslog syslog 4.0K Apr 12 08:26 .
         drwxr-xr-x 96 root   root    12K Apr 12 08:47 ..
         -rw-------  1 syslog syslog 8.0K Apr 12 08:09 ca-key.pem
         -rw-r--r--  1 syslog syslog 1.5K Apr 12 08:14 ca.pem
         -rw-------  1 syslog syslog 2.7K Apr 12 08:25 request.pem
         -rw-r--r--  1 syslog syslog 1.5K Apr 12 08:22 rslclient-cert.pem
         -rw-------  1 syslog syslog 5.6K Apr 12 08:15 rslclient-key.pem
         -rw-r--r--  1 syslog syslog 1.5K Apr 12 08:27 rslserver-cert.pem
         -rw-------  1 syslog syslog 5.5K Apr 12 08:24 rslserver-key.pem
      
### Configuring RSyslog server

Open `/etc/rsyslog.conf` and configure it as follows:

```
module(load="imuxsock")
module(load="imklog" permitnonkernelfacility="on")

module(load="imtcp" 
    StreamDriver.Name="gtls"
    StreamDriver.Mode="1"
    StreamDriver.Authmode="x509/name"
    PermittedPeer=["elastic.barrydegraaff.nl"]
    )

global(
    DefaultNetstreamDriver="gtls"
    DefaultNetstreamDriverCAFile="/etc/rsyslog-certs/ca.pem"
    DefaultNetstreamDriverCertFile="/etc/rsyslog-certs/rslserver-cert.pem"
    DefaultNetstreamDriverKeyFile="/etc/rsyslog-certs/rslserver-key.pem"
    )

    input(
    type="imtcp"
    port="514"
    )

$MaxOpenFiles 2048
$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat
$RepeatedMsgReduction on
$FileOwner syslog
$FileGroup adm
$FileCreateMode 0640
$DirCreateMode 0755
$Umask 0022
$PrivDropToUser syslog
$PrivDropToGroup syslog
$WorkDirectory /var/spool/rsyslog
$IncludeConfig /etc/rsyslog.d/*.conf

```

By setting this configuration you enforce TLS encryption and authentication on RSyslog. This means all traffic is encrypted and only trusted clients can log to our server.

Now restart the server and check if it listens:

      systemctl restart rsyslog
      netstat -tulpn | grep 514
         tcp        0      0 0.0.0.0:514             0.0.0.0:*               LISTEN      2451/rsyslogd    

Depending on your situation you can configure a (host) firewall or change the RSyslog listener to restrict network traffic. 0.0.0.0 means the entire ipv4 world can connect to RSyslog. Since we configured certificate authentication all connections are refused that are not coming from our trusted client(s). 

### References

- https://www.thegeekdiary.com/how-to-configure-rsyslog-server-to-accept-logs-via-ssl-tls/
- https://www.rsyslog.com/doc/master/tutorials/tls.html
- https://michlstechblog.info/blog/rsyslog-configure-tls-ssl/
- https://www.golinuxcloud.com/secure-remote-logging-rsyslog-tls-certificate/


## Configuring Zimbra to log to Centralized Log Server

This guide has been tested on Zimbra 8.8.15 and Zimbra 9 deployed on Ubuntu 20.04 LTS. Make sure to install all updates by running:

      apt update && apt upgrade

Consider rebooting your system if it has been up for longer than 30 days.

### Install the necessary packages

      apt install -y rsyslog rsyslog-gnutls

### Configuring RSyslog client

Open `/etc/rsyslog.conf` and configure it as follows:

```
module(load="imuxsock")
module(load="imklog" permitnonkernelfacility="on")

$DefaultNetstreamDriver gtls

$DefaultNetstreamDriverCAFile /etc/rsyslog-certs/ca.pem
$DefaultNetstreamDriverCertFile /etc/rsyslog-certs/rslclient-cert.pem
$DefaultNetstreamDriverKeyFile /etc/rsyslog-certs/rslclient-key.pem

$ActionSendStreamDriverPermittedPeer elastic.barrydegraaff.nl
$ActionSendStreamDriverMode 1
$ActionSendStreamDriverAuthMode x509/name

# forward everything to remote server
*.*     @@(o)elastic.barrydegraaff.nl:514

$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat
$RepeatedMsgReduction on
$FileOwner syslog
$FileGroup adm
$FileCreateMode 0640
$DirCreateMode 0755
$Umask 0022
$PrivDropToUser syslog
$PrivDropToGroup syslog
$WorkDirectory /var/spool/rsyslog

$ModLoad imfile

# error log
$InputFileName /opt/zimbra/log/nginx.error.log
$InputFileTag nginx:
$InputFileStateFile stat-nginx-error
$InputFileSeverity info
$InputFileFacility local6
$InputFilePollInterval 1
$InputRunFileMonitor

# access log
$InputFileName /opt/zimbra/log/nginx.access.log
$InputFileTag nginx:
$InputFileStateFile stat-nginx-access
$InputFileSeverity info
$InputFileFacility local6
$InputFilePollInterval 1
$InputRunFileMonitor

$InputFileName /opt/zimbra/log/audit.log
$InputFileTag zimbra-audit:
$InputFileStateFile zimbra-audit
$InputFileSeverity info
$InputFileFacility local0
$InputFilePollInterval 1
$InputRunFileMonitor

$IncludeConfig /etc/rsyslog.d/*.conf
```

You should use hosts that resolve over DNS so that TLS works. If you do not have a working DNS you can add a local hosts entry to `/etc/hosts`, make sure to use your own IP address and domain name:

      192.168.1.101 elastic.barrydegraaff.nl

Create and copy the certificates for TLS to the client:

      mkdir  /etc/rsyslog-certs

Next you have to copy the files `/etc/rsyslog-certs/ca.pem`, `/etc/rsyslog-certs/rslclient-cert.pem` and `/etc/rsyslog-certs/rslclient-key.pem` from your syslog server to your client and run:

      chown syslog:syslog /etc/rsyslog-certs -R

Finally it should look like this:

      ls -hal /etc/rsyslog-certs
         total 24K
         drwxr-xr-x  2 syslog syslog 4.0K Apr 12 09:37 .
         drwxr-xr-x 97 root   root   4.0K Apr 12 09:37 ..
         -rw-r--r--  1 syslog syslog 1.5K Apr 12 09:37 ca.pem
         -rw-r--r--  1 syslog syslog 1.5K Apr 12 09:37 rslclient-cert.pem
         -rw-------  1 syslog syslog 5.6K Apr 12 09:37 rslclient-key.pem

Give the syslog user access to the Zimbra audit log:

      usermod -a -G zimbra syslog

Now restart the server:

      systemctl restart rsyslog

### Test remote logs

Install `util-linux` package in case you do not have the logger command and on your Zimbra server run the command:

      echo "Hello World"  | logger -t "barrytest"

Then run `tail -f /var/log/syslog` on both the client and server to see if the log is received at the server. To debug if the server is using TLS you can use:

      openssl s_client -connect elastic.barrydegraaff.nl:514

This command should return CONNECTED and show the TLS server certificate. If all goes well you should see this log on the RSyslog server:

      Apr 12 11:23:32 zm-zimbra8 barrytest: Hello World

Some logs of Zimbra should already show up. Configure Zimbra Mailbox to send *all* logs to RSyslog by issuing:

      su zimbra
      zmprov mcf zimbraLogToSysLog TRUE
      zmcontrol restart

### Debugging RSyslog

If you have trouble getting logs into RSyslog you can enable debugging by adding below configuration to `/etc/rsyslog.conf`. For example if RSyslog does not have read permission to a specific log file you can find it this way. Don't forget `systemctl restart rsyslog`:

      $DebugLevel 2
      $DebugFile /root/RSYSLOG.txt


### References and notes

Note: In this article the Centralized Logging Server with Elastic Stack is running on Ubuntu 22 and Zimbra is running on a server with Ubuntu 20. The configuration syntax for remote logging using gtls driver in RSyslog differs between these versions and this is reflected in this guide.

- https://www.thegeekdiary.com/configuring-remote-logging-using-rsyslog-in-centos-rhel/
- https://zimbra.github.io/zimbra-9/adminguide.html#monitoring_zcs_servers
- https://wiki.zimbra.com/wiki/Log_Files


## Installing Elastic Stack

The information in this section is a shortened version from guides written by Digital Ocean. Links can be found under references.

### Installing Elasticsearch

Elasticsearch is the search engine that powers Elastic Stack. It needs Java so install that first:

      apt install default-jdk

Then proceed by installing:

      wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
      sudo apt-get install apt-transport-https
      echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
      sudo apt-get update
      sudo apt-get install elasticsearch

Elastic Stack 8 has introduced new security features called `xpack`. These features include encrypted connections and authentication between all components. Setting it up requires some effort. In this article we will disable `xpack` security features, which basically brings back the functionality as in Elastic Stack 7. Configure Elasticsearch to diable `xpack` and allow connections from the local machine only `sudo nano /etc/elasticsearch/elasticsearch.yml`:

```
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch

network.host: localhost
xpack.security.enabled: false

xpack.security.http.ssl:
  enabled: false

xpack.security.transport.ssl:
  enabled: false

cluster.initial_master_nodes: ["elastic.barrydegraaff.nl"]
```

Enable and start the service:

      sudo systemctl start elasticsearch #this takes a while...
      sudo systemctl enable elasticsearch

Test if it works:

      curl -X GET "localhost:9200"
      {
        "name" : "elastic.barrydegraaff.nl",
        "cluster_name" : "elasticsearch",
        "cluster_uuid" : "6g_cMTTCQdiP-KvpD9Uh-Q",
        "version" : {
          "number" : "8.6.2",
          "build_flavor" : "default",
          "build_type" : "deb",
          "build_hash" : "2d58d0f136141f03239816a4e360a8d17b6d8f29",
          "build_date" : "2023-02-13T09:35:20.314882762Z",
          "build_snapshot" : false,
          "lucene_version" : "9.4.2",
          "minimum_wire_compatibility_version" : "7.17.0",
          "minimum_index_compatibility_version" : "7.0.0"
        },
        "tagline" : "You Know, for Search"
      }
      
### Installing Kibana Dashboard

Kibana is the Web application that allows you to visualize the logs and create dashboards. According to the official documentation, you should install Kibana only after installing Elasticsearch. Installing in this order ensures that the components each product depends on are correctly in place.

      sudo apt install kibana
      sudo systemctl enable kibana

Open `/etc/kibana/kibana.yml` add add the following:

```
server.publicBaseUrl: "https://elastic.barrydegraaff.nl/"
security.showInsecureClusterWarning: false
```

Finally start Kibana:

      sudo systemctl start kibana

At this point Kibana Dashboard will work, but you still need to install Nginx to add TLS and authentication to the web UI.

      apt install nginx apache2-utils

Create a username and password for the WebUI, put your own username and password:

      htpasswd -bc /etc/nginx/htpasswd.users UserNameHere PasswordHere

Put the following config in `/etc/nginx/sites-enabled/default`. Configure your own ssl_certificate and key. This example used a Let's Encrypt certificate.


````
# Upstreams
upstream backend {
server 127.0.0.1:5601;
}

# HTTPS Server
server {
    listen 443 ssl;
    server_name elastic.barrydegraaff.nl;

    # You can increase the limit if your need to.
    client_max_body_size 200M;

    error_log /var/log/nginx/elastic.access.log;

    ssl_certificate /etc/letsencrypt/live/barrydegraaff.nl/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/barrydegraaff.nl/privkey.pem;
    
    # https://ssl-config.mozilla.org/#server=nginx&version=1.17.7&config=modern&openssl=1.1.1k&guideline=5.6
    ssl_session_timeout 1d;
    ssl_session_cache shared:MozSSL:10m;  # about 40000 sessions
    ssl_session_tickets off;

    # modern configuration
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers off;

    # HSTS (ngx_http_headers_module is required) (63072000 seconds)
    add_header Strict-Transport-Security "max-age=63072000" always;

    # OCSP stapling
    ssl_stapling on;
    ssl_stapling_verify on;

    auth_basic "Restricted Access";
    auth_basic_user_file /etc/nginx/htpasswd.users;

    location / {
        proxy_pass http://backend/;

        proxy_http_version 1.1;
        proxy_hide_header 'X-Frame-Options';
        proxy_hide_header 'Access-Control-Allow-Origin';

        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $http_host;

        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forward-Proto http;
        proxy_set_header X-Nginx-Proxy true;

        proxy_redirect off;
    }
}
````
Finally start Kibana and restart Nginx:

      sudo systemctl start kibana
      sudo systemctl restart nginx

In case you have a firewall open port 443 and then test if you can access Kibana from https://elastic.barrydegraaff.nl/status

![](screenshots/02-status.png)
*Kibana status screen.*

### Installing Logstash

Logstash is the Elastic Stack component that converts log files into a database. Once the conversion is done text values from the log become available as floating point values or whatever type is needed allowing for visualization. _These parsed log values are called fields._

To install Logstash:

      sudo apt install logstash

Put the following config files:

`/etc/logstash/conf.d/02-beats-input.conf`

```
input {
  beats {
    port => 5044
  }
}
```

`/etc/logstash/conf.d/30-elasticsearch-output.conf`

```
output {
  elasticsearch {
    hosts => ["localhost:9200"]
    manage_template => false
    index => "%{[@metadata][beat]}-%{[@metadata][version]}-%{+YYYY.MM.dd}"
  }
}
```

Enable and start the service:

      sudo systemctl start logstash
      sudo systemctl enable logstash


### Installing Filebeat

Filebeat is an Elastic Stack mechanism to transport log files from RSyslog to Logstash or Elasticsearch. Since we gather all the logging via RSyslog we only need one Filebeat configuration to transport everything.

      sudo apt install filebeat

Open the config file `/etc/filebeat/filebeat.yml` and configure it as follows:

```
filebeat.inputs:
- type: filestream
  id: zimbra-filestream
  enabled: true
  paths:
    - /var/log/syslog

filebeat.config.modules:
  path: ${path.config}/modules.d/*.yml
  reload.enabled: false

setup.template.settings:
  index.number_of_shards: 1

setup.dashboards.enabled: true

setup.kibana:
  host: "localhost:5601"

output.elasticsearch:
  hosts: ["localhost:9200"]

processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_cloud_metadata: ~
  - add_docker_metadata: ~
  - add_kubernetes_metadata: ~
```

Setup Filebeat index

      sudo filebeat setup --pipelines

This command should output:

      Loaded Ingest pipelines

Set-up indexes:

      sudo filebeat setup --index-management -E output.logstash.enabled=false -E 'output.elasticsearch.hosts=["localhost:9200"]'

The last command will take some time and you should get output similar to:

      Overwriting ILM policy is disabled. Set `setup.ilm.overwrite: true` for enabling.
      
      Index setup finished.

Finally enable Filebeat

      sudo systemctl start filebeat
      sudo systemctl enable filebeat
   
You should be able to see some logs in Observability > Logs > Stream. In case the UI has changed, the URL:
https://elastic.barrydegraaff.nl/app/logs/stream

![](screenshots/03-logstream.png)
*Some logs incoming after initial setup.*

### References and notes

Note: when running `filebeat setup` with `-E` or `-M` option one basically tells filebeat to ignore the config file options specified, this is to work around a bug. 

- https://www.digitalocean.com/community/tutorials/how-to-install-elasticsearch-logstash-and-kibana-elastic-stack-on-ubuntu-20-04
- https://www.digitalocean.com/community/tutorials/how-to-install-java-with-apt-on-ubuntu-20-04
- https://kifarunix.com/install-elk-stack-8-x-on-ubuntu/
- https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-filestream.html
- https://www.elastic.co/guide/en/beats/filebeat/current/configuration-filebeat-options.html

Bugs:

- https://www.reddit.com/r/elasticsearch/comments/w8g64e/problems_with_enabling_filesets_in_filebeat/
- https://github.com/elastic/beats/issues/30916

## Ingest Pipelines

Ingest Pipelines can be used to remove or transform fields, extract values from text, and enrich your data before indexing.

In an older version of this guide the adding of fields was done by configuring [/etc/logstash/conf.d/10-syslog-filter.conf](https://raw.githubusercontent.com/Zimbra/elastic-stack/main/rsyslog-elastic/logstash/conf.d/10-syslog-filter.conf). This no longer seems to work in Elasticsearch 8.x and can now be done via the UI.

In this version of the guide we switched to manual Filebeat and Ingress pipeline configuration. This will make it easier to maintain this guide as the Filebeat system module and automatically generated pipelines change frequently and require more complex debugging if they don't work. Some screenshots in this guide still show the automatically generated Ingest pipelines such as `filebeat-8.7.0-system-pipeline`. In the new version of the guide you will learn how to set-up a clean pipeline called `zimbra`.

If you completed the previous paragraph you should see logs coming into Elastic Stack. 

Go to Stack Management > Ingest Pipelines and click Create Pipeline.

![](screenshots/04-create-pipeline.png)

Set the name of the pipeline to `zimbra` and optionally set a version and description.

![](screenshots/05-zimbra-pipeline.png)


Elastic Stack uses a language called `grok` that relies on regular expressions to convert raw logs into fields. An example of CPU statistics logged from Zimbra:

      Apr 13 11:56:30 zm-zimbra8 zimbramon[17392]: 17392:info: zmstat cpu.csv: timestamp, cpu:user, cpu:nice, cpu:sys, cpu:idle, cpu:iowait, cpu:irq, cpu:softirq, cpu0:user, cpu0:nice, cpu0:sys, cpu0:idle, cpu0:iowait, cpu0:irq, cpu0:softirq, cpu1:user, cpu1:nice, cpu1:sys, cpu1:idle, cpu1:iowait, cpu1:irq, cpu1:softirq:: 04/13/2021 11:56:30, 8.6, 0.0, 1.9, 89.5, 0.1, 0.0, 0.0, 9.1, 0.0, 1.8, 89.0, 0.1, 0.0, 0.0, 8.0, 0.0, 2.0, 89.9, 0.0, 0.0, 0.0

This can be parsed with `grok` as follows:

```
zmstat cpu.csv:.*:: %{DATA:statdate} %{DATA:stattime}, %{NUMBER:cpu-user:float}, %{NUMBER:cpu-nice:float}, %{NUMBER:cpu-sys:float}, %{NUMBER:cpu-idle:float}, %{NUMBER:cpu-iowait:float}, %{NUMBER:cpu-irq:float}, %{NUMBER:cpu-soft-irq:float}
```

You can use this `grok` expression by adding it as a processor in the Zimbra pipeline. Click Add a processor under Processors. Make sure not to click the one under Failure processors.

![](screenshots/03-02-add-processor.png)

In the Manage Processor dialog, set the following:

| Field | value |
|---|---|
| Processor | Grok |
| Field | message |
| Patterns | `zmstat cpu.csv:.*:: %{DATA:statdate} %{DATA:stattime}, %{NUMBER:cpu-user:float}, %{NUMBER:cpu-nice:float}, %{NUMBER:cpu-sys:float}, %{NUMBER:cpu-idle:float}, %{NUMBER:cpu-iowait:float}, %{NUMBER:cpu-irq:float}, %{NUMBER:cpu-soft-irq:float}` |
| Ignore missing | checked |
| Condition | `ctx.message.contains('zmstat cpu.csv')` |
| Tag | cpucsv |
| Ignore failure | checked |

With the settings in the table we tell Ingress to apply the `grok` expression on a field called `Message`. The parsed `grok` result is then stored into new fields that can be used for further analysis and visualization. The `Condition` can be used to conditionally apply the `grok` expression, in this case only on logs coming from `zmstat cpu`. You can add multiple processors to deal with different types of logs.

Then click Add (or Update) and Save Pipeline.

![](screenshots/03-03-processor.png)

Configure Filebeat to use this pipeline for incoming logs, from the command line:

```
sudo nano /etc/filebeat/filebeat.yml
```

And add `pipeline: zimbra` under `filebeat.inputs` the complete config file will look like this:

```
filebeat.inputs:
- type: filestream
  id: zimbra-filestream
  pipeline: zimbra
  enabled: true
  paths:
    - /var/log/syslog

filebeat.config.modules:
  path: ${path.config}/modules.d/*.yml
  reload.enabled: false

setup.template.settings:
  index.number_of_shards: 1

setup.dashboards.enabled: true

setup.kibana:
  host: "localhost:5601"

output.elasticsearch:
  hosts: ["localhost:9200"]

processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_cloud_metadata: ~
  - add_docker_metadata: ~
  - add_kubernetes_metadata: ~
```

Then restart logstash and filebeat to load the change:

```
systemctl restart filebeat
systemctl restart logstash
```

Changes made to the Ingress Pipeline will be applied to newly received logs in Elastic Stack. You can see the new fields by going to Observability > Logs > Stream find a search for `"message":"zmstat cpu.csv"` and select View details for any of the displayed logs. The command line steps for configuring the pipeline only need to be done once.

![](screenshots/03-04-details-menu.png)

As you can see this log has additional fields called cpu-idle, cpu-iowait, cpu-sys etc.

![](screenshots/03-05-new-fields.png)

### Grok for failed login attempts from audit.log

You can add another processor in the Ingress Pipeline to find failed login attempts. Example authentication error from audit.log:

```
2023-02-21 07:15:18,581 WARN  [qtp1489092624-139://localhost:8080/service/soap/BatchRequest] [name=admin@zimbra8.barrydegraaff.nl;oip=192.168.1.126;ua=zclient/8.8.15_GA_4484;soapId=1a5ec841;] security - cmd=Auth; account=admin@zimbra8.barrydegraaff.nl; protocol=soap; error=authentication failed for [admin], invalid password;
```

The grok pattern to match:

```
.*name=%{DATA:failuser};.*p=%{DATA:failip};.*authentication failed for .*$
```

The result:
```
{
  "failuser": "admin@zimbra8.barrydegraaff.nl",
  "failip": "192.168.1.126"
}
```

### Using the `grok` debugger

When writing the `grok` filter you can use the `grok` debugger in the Kibana UI. This way you can make sure your regular expression matches the log, before adding it to Elastic Stack.

![](screenshots/37b-grok-debugger.png)
*The `grok` debugger tool*

### Debugging Ingress Pipelines

Sometimes fields are not added even if you tried the Grok debugger and have configured Filebeat correctly. In the Kibana web-interface there is a test feature that can be used to debug Ingress Pipelines.

Go to Stack Management > Ingest Pipelines > Edit the Zimbra pipeline then click Add documents

![](screenshots/06-test-pipeline.png)

Select Add test document from an index.

![](screenshots/06-02-document-from-index.png)

In another browser tab go to Observability > Logs > Stream and find a log entry that you would like to parse.

![](screenshots/06-01-example-log-entry.png)

In the top of the log entry you can find the Document ID and Index that can be used to add the test document. Copy paste the and click Add document:

![](screenshots/06-03-document-add.png)

Then click Run the pipeline to perform a test.

![](screenshots/06-03-document-added.png)

After the running the test you can scroll to your grok processor and an icon will indicate if the grok processor ran successful, had a failure or was skipped due to the condition configured in the condition field. An example of a failure:

![](screenshots/06-04-grok-fail.png)

More details can be found in the output tab:

![](screenshots/06-05-grok-fail-output.png)

While debugging it is best to set the following in your grok processor:

| Field | value |
|---|---|
| Ignore missing | unchecked |
| Ignore failure | unchecked |

Once it works, change these back to checked, and click save on both your grok processor and your pipeline.

## Understanding Kibana UI

This chapter is a walk-through for the Kibana UI. It shows the locations in the Kibana UI where you can find and analyze if the configuration of the previous steps in this guide are working. In the next chapter this guide will show you how to define more fields for logs that Elastic Stack is not parsing yet.

### Observability

In Observability > Logs you can see log data as they come into Elastic Stack using the Stream Live option. If some log is missing here, it means it did not pass from RSyslog to Filebeat and you have to go back to the command line for Rsyslog debugging and look at the Ingest Pipeline chapter to fix it `grok` patterns. 

![](screenshots/10-observability-logs.png)
*Logs are in Observability/Logs.*

![](screenshots/10-observability-logs-stream.png)
*Analyze logs as they are received in Observability/Logs.*

### Analyzing

By using Analyzing > Discover you can see what logs have been processed by Elastic Stack and if the conversion to fields was successful. You can also use the Search feature to do ad-hoc analyzing of logs. Click View Details to find fields you have added in the `grok` filter configuration file. In our case these fields have names that start with `cpu-`.

![](screenshots/11-analytics-discover.png)
*Dig into the parsed logs in Analytics/Discover.*

![](screenshots/12-analytics-discover-search.png)
*Search for a log and expand the details.*

![](screenshots/14-analytics-discover-log-detail-zimbra.png)
*Find Zimbra specific fields available for visualization.*



## Adding visualizations

In Kibana you can define one or more dashboards to visualize statistics of your Zimbra environment. The easiest way to create visualizations is to first search for the logs that you need, then select the fields from those logs that you want to visualize. If the search works correctly you can save the search and use it for visualization in a dashboard.

### Adding a count visualization (without field)

The count visualization is the simplest form of visualization in Kibana. It counts the number of times a specific log entries matches a search query. Benefits of this visualization is that it just works by searching through the `message` field, which is basically a raw line of log data. So you do not need to parse fields with a `grok` filter.

First navigate to Analysis > Discover or in older versions Kibana > Discover. Use the search field to find the logs. Here are some Postfix examples:

- `message:"postfix" and message:"status=bounced"`
- `message:"postfix" and message:"status=deferred"`
- `message:"postfix" and message:"status=sent"`

![](screenshots/15-count-visualization.png)
*Searching for Postfix logs.*

Once you are satisfied with your query, hit the Save button.

#### Create the count visualization

To create a visualization go to Analytics > Visualize Library. Or if you use an older version go to Kibana > Visualize. 

![](screenshots/16-create-visualization.png)
*Click Create Visualization.*

![](screenshots/17-aggregation-based.png)
*Select Aggregation based.*

![](screenshots/18-area.png)
*Select Area.*

![](screenshots/19-saved-search-as-source.png)
*Next select your saved search.*

Now Kibana will show the saved search on the X axis, but since we did not specify anything else, it is just one big bar that counts all the logs, not really useful.

![](screenshots/20-visual-but-not-configured.png)
*After selecting the source data, we see a count of all logs, but that is not useful.*

For the Y axis select Aggregation > Count and for X axis select Aggregation > Date Histogram and use the @timestamp field. The timestamp is the time and date that was parsed from the log file. There are many detailed settings which this guide does not explain, you can play around with them and hit the Save button once you are ready.

Here are some screenshots that show the final result:

![](screenshots/21-visualization-tab1.png)
*X and Y axis configured.*

![](screenshots/21-visualization-tab2.png)
*Metrics and Axis allow configuring some details with regards to chart type and mode etc.*

![](screenshots/21-visualization-tab3.png)
*The Panel tab allows for tweaking the way the visualization is displayed in a Dashboard.*

Don't forget to hit Save. Upon saving you will be asked to create a new dashboard, save to an existing dashboard or just save the visualization without adding it to a dashboard. You can create a new dashboard if you wish or create a new dashboard later.

#### Create a dashboard

Create a new Dashboard by going to Analytics > Dashboard. 

![](screenshots/23-new-dashboard.png)
*Click Add from Library and search your saved visualization.*

![](screenshots/24-result-in-dashboard.png)
*The visualization is now on the Dashboard.*

Don't forget to click Save to save the Dashboard.


### Adding a number visualization (existing field)

Kibana can also create visualization based on parsed values (fields) from your logs. This way you can create line charts to get insights into things like CPU, RAM, and disk usage etc. This only works if Elastic Stack has parsed the RAW log into fields using a `grok` filter. The filter also tells Kibana what type of number is expected, for example floating point or integer.

To visualize the CPU statistics using the `grok` pattern from the Ingest Pipeline chapter, navigate to Analysis > Discover or in older versions Kibana > Discover. Use the search field to find the logs from vmstat. By using:

- `"zmstat cpu.csv"`

And select the fields needed for visualization:

![](screenshots/25-discover.png)
*Searching for logs and select fields.*

Once the fields are selected, you will see them displayed as columns on the screen:

![](screenshots/28-selected.png)
*Columns selected for visualization.*

Once you are satisfied with your query, hit the Save button.

#### Create the number visualization

To create a visualization go to Analytics > Visualize Library. Or if you use an older version go to Kibana > Visualize. 

![](screenshots/16-create-visualization.png)
*Click Create Visualization.*

![](screenshots/17-aggregation-based.png)
*Select Aggregation based.*

![](screenshots/29-line.png)
*Select Line.*

![](screenshots/30-saved-search-as-source.png)
*Next select your saved search.*

Now Kibana will show the saved search and try to guess how to visualize it. In most cases the settings for the X axis are messed up and you will need to configure it to make sense.

For the Y axis select Aggregation > Max and select a field from the saved query. Repeat this for all fields. For X axis select Aggregation > Date Histogram and use the @timestamp field. The timestamp is the time and date that was parsed from the log file. Hit the Save button once you are ready. 

Here are some screenshots that show the final result:

![](screenshots/31-y.png)
*Multiple Y axis configured.*

![](screenshots/32-x.png)
*X axis configured.*

![](screenshots/33-timeframe.png)
*Sometimes expanding the time range makes it easier to get a good visualization.*

![](screenshots/34-result-in-8.png)
*An example of a CPU visualization in Elastic Stack 8.*

Don't forget to hit Save.

#### Adding the visualization to the dashboard

If you already have a Dashboard you can open it by going to Analytics > Dashboard. Then click Edit. Then click the Add from library button or the Add menu item in older versions. For more information on how to create a dashboard see the previous chapter. The final result will look something like this:

![](screenshots/34-result-line.png)
*The visualization is now on the Dashboard.*

Don't forget to click Save to save the Dashboard.

#### References

- https://access.redhat.com/solutions/1160343
- https://wiki.zimbra.com/wiki/Zmstats

### Adding a percentage visualization (new field)

Imagine you have a custom process or you want to track something in Elastic Stack that is not logged yet. This chapter shows you how to add a new field to Elastic Stack and how to add custom logging via a BASH script.

In this example you learn how to create Gauge visualizations to show the percentage of a BASH script output.

![](screenshots/35-gauges.png)
*Gauges are a great way to simplify a statistic.*

#### Create a BASH script

Create a BASH script `/usr/local/sbin/zimbra-simple-stat.sh` on the RSyslog client. With the following content:

```
#!/bin/bash

# Yes it is a bit ugly, but it works.
# Tear it apart if you want to find out how it works.
echo "CPU `LC_ALL=C top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}'`% RAM `free -m | awk '/Mem:/ { printf("%3.1f%%", $3/$2*100) }'` HDD `df -h / | awk '/\// {print $(NF-1)}'`"  | logger -t "zimbra-simple-stat"
```

Don't forget to mark it executable and run it once to test:

      chmod +rx /usr/local/sbin/zimbra-simple-stat.sh
      /usr/local/sbin/zimbra-simple-stat.sh

Test the output of the script on the **RSyslog server** by running:

      cat /var/log/syslog | grep "zimbra-simple-stat"
         Apr 15 12:38:01 mind zimbra-simple-stat: CPU 65.1% RAM 77.8% HDD 20%

Run the script every minute so a log appears that can be used in Elastic Stack. Add the following to `/etc/crontab` on the RSyslog client:

      * * * * * root /usr/local/sbin/zimbra-simple-stat.sh

Now add the following `grok` processor to the Ingress Pipeline, refer to the Ingress Pipelines chapter if needed:

| Field | value |
|---|---|
| Processor | Grok |
| Field | message |
| Patterns | `CPU %{NUMBER:zimbra_simplestat_cpu:float}% RAM %{NUMBER:zimbra_simplestat_ram:float}% HDD %{NUMBER:zimbra_simplestat_hdd:float}%` |
| Ignore missing | checked |
| Condition | `ctx.process.name.contains('zimbra-simple-stat')` |
| Tag | zimbra-simple-stat |
| Ignore failure | checked |

This processor is only applied to logs from the zimbra-simple-stat process as defined in the Condition. The `grok` expression parses the fields needed for visualization.

For example the field `zimbra_simplestat_cpu` is defined and the log value will be stored as a floating point number:

         CPU %{NUMBER:zimbra_simplestat_cpu:float}%

Now navigate to Analytics > Discover. Use the search field to find the logs by using:

- `process.name:"zimbra-simple-stat"`

![](screenshots/36-simplestat-discover.png)
*Searching for zimbra-simple-stat logs.*

Next verify that the field `zimbra_simplestat_cpu` is parsed in the log by expanding the details. Then select the field.

![](screenshots/37-select-verify-field.png)
*Selecting the `zimbra_simplestat_cpu` field.*

Once you are satisfied with your query, hit the Save button.

#### Create the percentage visualization

To create a visualization go to Analytics > Visualize Library. Or if you use an older version go to Kibana > Visualize. 

![](screenshots/16-create-visualization.png)
*Click Create Visualization.*

![](screenshots/17-aggregation-based.png)
*Select Aggregation based.*

![](screenshots/38-gauge-visualization.png)
*Select Gauge.*

![](screenshots/39-select-cpu-saved-search.png)
*Next select your saved search.*

Now Kibana will show the count of the saved search or some other guesswork that does not make sense. Maybe one day Kibana will guess it right or actually make a wizard that is complete, in the mean time you have to configure the visualization to make useful. On the Metric select Max and select the field `zimbra_simplestat_cpu
`. You have to click the Update button to see the changes. Additionally in many cases you will want to expand or play with the time window to make sure the visualization works correctly.

![](screenshots/40-update-button.png)
*After configuring the Gauge click the update button.*

Don't forget to hit Save.

#### Adding the visualization to the dashboard

If you already have a Dashboard you can open it by going to Analytics > Dashboard. Then click Edit. Then click the Add from library button or the Add menu item in older versions. For more information on how to create a dashboard see the previous chapters. 

#### Showing only integers for percentage values

__This bug is fixed in Elastic Stack 8__

There is a bug in Kibana that prevents the setting of the amount of decimal places to display in Gauges. So your CPU statistic can show something funny like 56.32333%. To make it show only 56% you have to change the default pattern for percent in Stack Management > Advanced Settings. The default setting is `0,0.[000]%` and needs to be changed to `0%`.


![](screenshots/41-percentage-format.png)
*Configuring the default format for percentages.*

It is in the process of being fixed, so you may no longer need to do this. See also:

- https://github.com/elastic/kibana/issues/89404





## Monitoring in Kibana using Heartbeat

Kibana also has a way to do basic up-time monitoring. It can send ping requests, check HTTP status codes and open TCP sockets. Additionally it can check the TLS certificate expiration date.

The built-in monitoring is nice for statistics, but it cannot really determine if Zimbra is up and running in all cases. So it is a good idea to either add some custom scripting to be sure to capture downtime or have a different application for monitoring and alerting.

### Installing Heartbeat

      apt-get update 
      sudo apt-get install heartbeat-elastic
      systemctl enable heartbeat-elastic

Adapt the following configuration and place it in `/etc/heartbeat/monitors.d/zimbra.yml`:

```
- type: http
  schedule: '@every 5s'
  urls: ["https://mind.zimbra.io:443","https://mind.zimbra.io:7071/zimbraAdmin/"]
  tags: ["zimbra"]
  check.response.status: 200
  ssl:
      verification_mode: none

- type: tcp
  schedule: '@every 5s'
  hosts: ["mind.zimbra.io"]
  ports: [25]
  tags: ["zimbra"]

- type: tcp
  schedule: '@every 5s'
  hosts: ["167.71.67.26"]
  ports: [389]
  tags: ["zimbra"]

- type: tcp
  schedule: '@every 5s'
  hosts: ["167.71.67.26"]
  ports: [7025, 7143, 7110, 7993, 7995]
  tags: ["zimbra"]

- type: tcp
  schedule: '@every 5s'
  hosts: ["167.71.67.26"]
  ports: [25, 143, 110, 993, 995]
  tags: ["zimbra"]

# 25    - smtp (7025)
# 143   - imap (7143)
# 993   - imaps (7993)
# 110   - pop3 (7110)
# 995   - pop3s (7995)
```

Finally run:

      heartbeat setup -e
      systemctl restart heartbeat-elastic

You should now see a new menu item in Kibana under Observability > Uptime that looks like this:

![](screenshots/42-heartbeat.png)
*Kibana Uptime application.*


## Bonus: Grok patterns for Audit and Nginx log

__This chapter is written for and last verified for ELK 7.x it may not work for you. See the chapter Grok for failed login attempts from audit.log above to do the same on ELK 8.x.__

In this bonus chapter your can find `grok` patterns for the authentication log (/opt/zimbra/log/audit.log) and the proxy log (/opt/zimbra/log/nginx.access.log). These can be used in case you want to use `filebeat` to read the logs directly and not use centralized logging based on RSyslog.

### Filebeat configuration

Open `/etc/filebeat/filebeat.yml` using nano and add the configuration under `filebeat.inputs`:

```
filebeat.inputs:

- type: log
  enabled: true
  paths:
    - /opt/zimbra/log/activity.log
  fields:
    log_type: zimbra_kavach
    fields_under_root: true

- type: log
  paths:
    - /opt/zimbra/log/audit.log
  fields:
    log_type: zimbra_audit
    fields_under_root: true
```

### Logstash configuration

Create following configuration files in `/etc/logstash/conf.d/` and given grok patterns in `/etc/logstash/patterns/`.

Create a file named `18-filter-audit.conf` and copy following content:

```
filter {
  if [fields][log_type] == "zimbra_audit" {
    grok {
        patterns_dir => ["/etc/logstash/patterns/audit"]
        match => ["message", "%{ZMAUDIT}"]
        add_tag => ["audit"]
        remove_tag => [ "unknown" ]
    }
  }
}
```

Create a file named `17-nginx-filter.conf` and copy following content:

```
filter {
  if [fields][log_type] == "zimbra_proxy" {
    grok {
        patterns_dir => ["/etc/logstash/patterns/nginx"]
        match => ["message", "%{NGINXACCESS}"]
        add_tag => ["nginx_access"]
        remove_tag => [ "unknown" ]
    }
  }
}
```

Create a directory `/etc/logstash/patterns`.

Add a file named `audit` to the patterns directory with the following content:

```
ZMQTP \[qtp%{NUMBER:qtp_process}-%{DATA:qtp_thread}:%{DATA:qtp_info}\]
ZMLOGLEVEL %{WORD:level}
ZMPROCESS %{DATA:zm_process}
ZMTHREAD %{NONNEGINT:thread}
ZMUSERAGENT %{DATA:user_agent}(/| - )%{DATA:user_agent_ver}
ZMPROGRAM \[%{ZMPROCESS}(-%{ZMTHREAD})?(:%{DATA:program_info})?\]
ZMCLIENT \[(name=%{DATA:account};)?(aname=%{DATA:delegated_username};)?(mid=%{NUMBER:mid};)?(ip=%{IPORHOST:sourceIP};)?(oip=%{IPORHOST:clientIP}, %{IPORHOST:sourceIP};)?(oproto=%{DATA:oproto};)?(port=%{NUMBER:oport};)?(DeviceID=%{DATA:device};)?(oip=%{IPORHOST:clientIP}(, %{IPORHOST:ProxyIP})?;)?(via=%{DATA:via};)?(cid=%{NUMBER:cid};)?(ua=%{ZMUSERAGENT};)?(soapId=%{DATA:soapId};)?\]
ZMCOMMAND cmd=%{WORD:command}
ZMCOMMAND_PARAMS (%{WORD:username_type}=%{DATA:username}(; protocol=%{WORD:protocol})?(; error=%{DATA:error})?(; feature=%{WORD:feature})?(; member=%{DATA:member})?(; status=%{WORD:status})?;)?
ZMAUDIT %{TIMESTAMP_ISO8601:stimestamp} %{ZMLOGLEVEL}  %{ZMPROGRAM} %{ZMCLIENT} security - %{ZMCOMMAND};( %{ZMCOMMAND_PARAMS})?
```

Add a file named `nginx` to the patterns directory with the following content:

```
NGINXACCESS %{IPORHOST:clientIP}:%{POSINT:port} - - \[%{HTTPDATE:stimestamp}\]  "%{WORD:method} %{URI:request} HTTP/%{NUMBER:httpversion}" %{NUMBER:http_code} (?:%{NUMBER:bytes:int}|-) (?:"(?:%{URI:referrer}|-)"|%{QS:referrer}) %{QS:agent} "%{IPORHOST:mailboxip}:%{POSINT:mailboxport}" "%{IPORHOST:proxyip}:%{POSINT:proxyport}"
```

### Visualizations from Audit log

Using the data from the Audit log one can display unique log-ins for all protocols or differentiate between for example IMAP and webmail log-ins. Also one can keep track of failed log-in attempts.

![](screenshots/bonus-audit.jpg)
*Visualizations from Audit log.*

### Visualizations from Nginx log

Using the data from the Nginx log one can display the number of server responses grouped by HTTP response code. This can give you some insight in how well your platform is working. Given that HTTP status 200 indicates an OK response and HTTP 500 means an error has occurred. The visualizations can also be used to show the server load in a given time frame.

![](screenshots/bonus-nginx.jpg)
*Visualizations from Nginx log.*

## References

- https://logz.io/blog/logstash-grok/
- https://www.elastic.co/guide/en/logstash/current/plugins-filters-grok.html
- https://alexmarquardt.com/using-grok-with-elasticsearch-to-add-structure-to-your-data/
- https://www.elastic.co/guide/en/elasticsearch/reference/master/ingest.html
- https://www.digitalocean.com/community/tutorials/adding-logstash-filters-to-improve-centralized-logging


### BSD 3-Clause License

Copyright (c) 2023, Synacor, Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
