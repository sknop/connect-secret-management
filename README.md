# connect-secret-management
Little tool to upload secrets for Kafka Connectors

usage: connect-secret-manager.py [-h] -p PASSWORD_FILE [-c CONFIG_FILE] [--url URL] [--certificate-file CERTIFICATE_FILE] [--username USERNAME] [--password PASSWORD]

Connect Secret Manager

optional arguments:
  -h, --help            show this help message and exit
  -p PASSWORD_FILE, --password-file PASSWORD_FILE
                        Password file
  -c CONFIG_FILE, --config-file CONFIG_FILE
                        Configuration file for URL and passwords
  --url URL             URL of a connect instance
  --certificate-file CERTIFICATE_FILE
                        Optional certificate file (pem format)
  --username USERNAME   Username
  --password PASSWORD   Password

You need to specify a connect instance for the URL including the scheme (http::// or https://), followed by the port,
for example "--url https://connect-cluster.example.com:8083"

The password file contains one block for each connector, separated by a blank line, as shown in the example file,
for example

connector1
username1
password1

connector2
username2
password2

Inside your connector, you should then use stanzas like below to use the secrets:

producer.override.sasl.jaas.config:
org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required username="${secret:connector1:username}" password="${secret:connector2:password}" metadataServerUrls="https://ip-172-30-22-106.eu-west-1.compute.internal:8090,https://ip-172-30-28-235.eu-west-1.compute.internal:8090";

converter.basic.auth.info:
${secret:connector1:username}:${secret:connector2:password}

