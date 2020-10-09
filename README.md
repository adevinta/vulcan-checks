# Vulcan Checks
This repository holds the code for each Vulcan check's main binary.

## Vendoring
Currently there's no vendoring provided for this project.

## Current list of [Checks](https://github.com/adevinta/vulcan-checks/tree/master/cmd)
1. **vulcan-aws-alerts** - Warns about CA issues in AWS RDS
1. **vulcan-aws-trusted-advisor** - Checks AWS Trusted Advisor for security findings
1. **vulcan-certinfo** - Extracts information about SSL/TLS certificates
1. **vulcan-dkim** - Checks if a domain (asset with a SOA record) have valid DNS configuration for DKIM 
1. **vulcan-dmarc** - Checks if a domain (asset with a SOA record) have valid DNS configuration for DMARC
1. **vulcan-docker-image** - Warns about outdated packages in docker Image
1. **vulcan-drupal** - Checks for vulnerabilities in Drupal CMS
1. **vulcan-exposed-amt** - Checks if an asset has the Intel AMT port exposed and whether is it vulnerable or not
1. **vulcan-exposed-bgp** - Checks for exposed BGP port on Internet routers
1. **vulcan-exposed-db** - Checks if an asset has open database well known ports
1. **vulcan-exposed-files** - Check asset for sensitive files exposed on HTTP server
1. **vulcan-exposed-ftp** - Checks if an asset has open FTP well known ports and if they allow anonymous logins or vulnerable to bounce attack
1. **vulcan-exposed-hdfs** - Checks if an EMR cluster is exposed to the Internet
1. **vulcan-exposed-http** - Checks if an asset has open HTTP well known ports
1. **vulcan-exposed-http-endpoint** - Warns about private resources that are exposed over http/https 
1. **vulcan-exposed-http-resources** - Checks if a web address exposes sensitive resources
1. **vulcan-exposed-memcached** - Checks if an asset has exposed a memcached server
1. **vulcan-exposed-rdp** - Checks if an Microsoft Remote Desktop service is exposed to the Internet
1. **vulcan-exposed-router-ports** - Checks if an asset has open router well known ports
1. **vulcan-exposed-services** - Checks if a host has any port opened by scanning the 1000 most common TCP and UDP ports
1. **vulcan-exposed-ssh** - Checks SSH server configuration for compliance with Mozilla OpenSSH guidelines
1. **vulcan-exposed-varnish** - Checks if an asset is a Web Cache, and also if it is a Varnish
1. **vulcan-gozuul** - Checks if a Zuul Gateway is vulnerable to Remote Code Execution as specified in nflx-2016-003
1. **vulcan-heartbleed** - Checks if an asset is vulnerable to heartbleed vulnerability
1. **vulcan-host-discovery** - Performs a quick Nmap ping scan that identifies which hosts are up
1. **vulcan-http-headers** - Analyzes the security of a website based on its HTTP headers
1. **vulcan-ipv6** - Checks for IPv6 presence
1. **vulcan-lucky** - Checks if an TLS asset is vulnerable to LuckyMinus20 attack
1. **vulcan-masscan** - Checks if a host has any port opened by scanning the whole TCP port range using masscan
1. **vulcan-mx** - Looks for MX DNS Records on a given domain
1. **vulcan-nessus** - Runs a Nessus scan
1. **vulcan-prowler** - Checks compliance against CIS AWS Foundations Benchmark
1. **vulcan-results-load-test** - Internal testing check, not for production
1. **vulcan-retirejs** - Checks for vulnerabilities in JS frontend dependencies
1. **vulcan-s3-takeover** - Checks for a vulnerability related to domain names pointing to a S3 static website when the S3 bucket has been deleted
1. **vulcan-seekret** - Checks if a Git repository contains secrets like passwords, API tokens or private keys
1. **vulcan-sleep** - Internal testing check, not for production
1. **vulcan-smtp-open-relay** - Checks for exposed SMTP, and if they are open relay
1. **vulcan-spf** - Checks if a domain (asset with a SOA record) have valid DNS configuration for SPF 
1. **vulcan-tls** - Analyzes TLS health of an asset
1. **vulcan-trivy** - Checks if a Docker image uses vulnerable packages or dependencies using Trivy
1. **vulcan-unclassified** - Example vulnerability to test the monitoring of unclassified vulnerabilities - not for production
1. **vulcan-vulners** - Runs https://vulners.com/api/v3/burp/software/
1. **vulcan-wpscan** - Checks Wordpress sites for vulnerabilities using the open source wpscan utility
1. **vulcan-zap** - Checks for vulnerabilities in web applications using OWASP ZAP
