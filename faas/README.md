# OpenFaaS

## Runtime

Use a kubernetes cluster (i.e. `k3d`)

```sh
k3d create --server-arg "--no-deploy=traefik" --server-arg "--no-deploy=servicelb"
export KUBECONFIG="$(k3d get-kubeconfig --name='k3s-default')"
```


## Setup Openfaas

Many options, here just one that works.

```sh
ark install openfaas --set faasIdler.dryRun=false
```

Follow the instructions and you should be able to access the console in http://localhost:8080/

## Work with functions

Build the functions

```sh
export DOCKER_USER=user

faas-cli build -f ./checks.yaml --parallel 4

faas-cli push -f ./checks.yaml

faas-cli deploy -f ./checks.yaml --label "com.openfaas.scale.zero=true"
```

List the deployed functions:

```sh
faas-cli list
Function                      	Invocations    	Replicas
vulcan-docker-image           	0              	0
vulcan-heartbleed             	0              	0
vulcan-exposed-services       	0              	0
vulcan-exposed-bgp            	0              	0
vulcan-dmarc                  	0              	0
vulcan-exposed-http           	0              	0
vulcan-host-discovery         	0              	0
vulcan-tls                    	0              	0
vulcan-sleep                  	0              	0
vulcan-s3-takeover            	0              	0
vulcan-results-load-test      	0              	0
vulcan-http-headers           	0              	0
vulcan-ipv6                   	0              	0
vulcan-unclassified           	0              	0
vulcan-exposed-amt            	0              	0
vulcan-seekret                	0              	0
vulcan-drupal                 	0              	0
vulcan-wpscan                 	0              	0
vulcan-trivy                  	0              	0
vulcan-retirejs               	0              	0
vulcan-spf                    	0              	0
vulcan-exposed-files          	0              	0
vulcan-exposed-memcached      	0              	0
vulcan-dkim                   	0              	0
vulcan-zap                    	0              	0
vulcan-gozuul                 	0              	0
vulcan-exposed-http-endpoint  	0              	0
vulcan-lucky                  	0              	0
vulcan-exposed-hdfs           	0              	0
vulcan-exposed-router-ports   	0              	0
vulcan-aws-alerts             	5              	0
vulcan-aws-trusted-advisor    	0              	0
vulcan-vulners                	0              	0
vulcan-exposed-db             	0              	0
vulcan-exposed-http-resources 	0              	0
vulcan-mx                     	0              	0
vulcan-masscan                	0              	0
vulcan-exposed-varnish        	0              	0
vulcan-exposed-rdp            	0              	0
vulcan-nessus                 	0              	0
vulcan-exposed-ssh            	0              	0
vulcan-exposed-ftp            	0              	0
vulcan-smtp-open-relay        	0              	0
vulcan-certinfo               	28             	1
```

## Call a function

Create a http server to mock the agent:
```sh
kubectl create deployment agent --image mendhak/http-https-echo:latest
kubectl create service clusterip agent --tcp=80:80

kubectl logs deployment/agent
```

And execute a check:

```sh
curl -X POST http://localhost:8080/function/vulcan-certinfo \
    --data '{"VULCAN_CHECK_TARGET":"www.gmail.com", "VULCAN_AGENT_ADDRESS": "agent"}'
```