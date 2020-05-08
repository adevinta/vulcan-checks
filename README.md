# Vulcan Checks
This repository holds the code for each Vulcan check's main binary.

## Vendoring
Currently there's no vendoring provided for this project.

## Current list of [Checks](https://github.com/adevinta/vulcan-checks/tree/master/cmd)
1. **vulcan-dkim** - Checks if a domain (asset with a SOA record) have valid DNS configuration for DKIM
2. **vulcan-spf** - Checks if a domain (asset with a SOA record) have valid DNS configuration for SPF
3. **vulcan-dmarc** - Checks if a domain (asset with a SOA record) have valid DNS configuration for DMARC
4. **vulcan-ipv6** - Checks for IPv6 presence
5. **vulcan-exposed-amt** - Checks if an asset has the Intel AMT port exposed and whether is it vulnerable or not
6. **vulcan-exposed-ssh** - Checks SSH server configuration for compliance with Mozilla OpenSSH guidelines
7. **vulcan-exposed-ftp** - Checks if an asset has open FTP well known ports and if they allow anonymous logins or vulnerable to bounce attack
8. **vulcan-smtp-open-relay** - Checks for exposed SMTP, and if they are open relay
9. ~~**vulcan-csp-report-uri** - Checks if an asset (site) has a proper defined CSP header and if violations are being reported to Argus~~
10. **vulcan-exposed-varnish** - Checks if an asset is a Web Cache, and also if it is a Varnish
11. **vulcan-exposed-http** - Checks if an asset has open HTTP well known ports
12. **vulcan-exposed-db** - Checks if an asset has open database well known ports
13. **vulcan-heartbleed** - Checks if an asset is vulnerable to heartbleed vulnerability
14. **vulcan-lucky** - Checks if an TLS asset is vulnerable to LuckyMinus20 attack
15. **vulcan-s3-takeover** - Checks for a vulnerability related to domain names pointing to a S3 static website when the S3 bucket has been deleted
16. **vulcan-tls** - Analyzes TLS health of an asset
17. **vulcan-wpscan** - Checks Wordpress sites for vulnerabilities using the open source wpscan utility
18. **vulcan-exposed-bgp** - Checks for exposed BGP port on Internet routers
19. **vulcan-exposed-router-ports** - Checks if an asset has open router well known ports
20. **vulcan-mx** - Looks for MX DNS Records on a given domain
21. **vulcan-certinfo** - Extracts information about SSL/TLS certificates
22. **vulcan-nessus** - Runs a Nessus scan
23. **vulcan-gozuul** - Checks if a Zuul Gateway is vulnerable to Remote Code Execution as specified in nflx-2016-003
24. **vulcan-http-headers** - Analyzes the security of a website based on its HTTP headers
25. **vulcan-exposed-files** - Check asset for sensitive files exposed on HTTP server
26. **vulcan-exposed-memcached** - Checks if an asset has exposed a memcached server
27. **vulcan-retirejs** - Checks for vulnerabilities in JS frontend dependencies
28. **vulcan-drupal** - Checks for vulnerabilities in Drupal CMS
29. **vulcan-zap** - Checks for vulnerabilities in web applications using OWASP ZAP
30. **vulcan-aws-trusted-advisor** - Checks AWS Trusted Advisor for security findings
31. **vulcan-exposed-services** - Checks if a host has any port opened by scanning the 1000 most common TCP and UDP ports
32. **vulcan-host-discovery** - Performs a quick Nmap ping scan that identifies which hosts are up
33. **vulcan-masscan** - Checks if a host has any port opened by scanning the whole TCP port range using masscan
34. **vulcan-exposed-endpoint** - Checks if well known or provided paths are present in a http url
35. **vulcan-exposed-hdfs** - Checks if an EMR cluster is exposed to the Internet
36. **vulcan-exposed-rdp** - Checks if an Microsoft Remote Desktop service is exposed to the Internet
37. **vulcan-seekret** - Checks if a Git repository contains secrets like passwords, API tokens or private keys
38. **vulcan-trivy** - Checks if a Docker image uses vulnerable packages or dependencies using Trivy
39. **vulcan-exposed-http-resources** - Checks if a web address exposes sensitive resources
