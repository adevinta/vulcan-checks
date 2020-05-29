# OpenFaaS

## Runtime

Use a kubernetes cluster (i.e. `k3d`)

```sh
docker volume create local-registry

k3d create --api-port 6550 --publish 8081:80 --publish 443:443 --server-arg "--no-deploy=traefik" --server-arg "--no-deploy=servicelb" --enable-registry --registry-volume local-registry

export KUBECONFIG="$(k3d get-kubeconfig --name='k3s-default')"

# Add nginx ingress controller OPTIONAL
arkade install nginx-ingress --host-mode
```

## Setup Openfaas

Many options, here just one that works.

```sh
ark install openfaas --set faasIdler.dryRun=false

kubectl port-forward svc/gateway --namespace openfaas 8080:8080 &
```

Access to the OpenFaaS system.

```sh
export OPENFAAS_PASSWORD=$(kubectl -n openfaas get secret basic-auth -o jsonpath="{.data.basic-auth-password}" | base64 --decode) && echo "OpenFaaS admin password: $OPENFAAS_PASSWORD"
export OPENFAAS_URL=http://localhost:8080/

echo $OPENFAAS_PASSWORD | faas login --password-stdin

faas list
```

## Work with functions

Build the functions

```sh
export DOCKER_USER=registry.local:5000/checks

faas-cli build -f ./stack.yml --parallel 4
faas-cli push -f ./stack.yml
faas-cli deploy -f ./stack.yml --label "com.openfaas.scale.zero=true"

# Or just
faas-cli up -f ./stack.yml --label "com.openfaas.scale.zero=true"
```

## Call a function

Create a http server to mock the agent:

```sh
kubectl create deployment mock-agent --image mendhak/http-https-echo:latest
kubectl create service clusterip mock-agent --tcp=80:80

kubectl logs deployment/mock-agent
```

And execute a check:

```sh
curl -X POST http://localhost:8080/function/vulcan-certinfo \
    --data '{"VULCAN_CHECK_ID":"123", "VULCAN_CHECKTYPE_NAME":"123", "VULCAN_CHECKTYPE_VERSION":"123", "VULCAN_CHECK_OPTIONS":"", "VULCAN_CHECK_TARGET":"www.adevinta.com", "VULCAN_AGENT_ADDRESS":"mock-agent.default"}'
```

## New checks

```sh
faas new --lang check-python3-http my-awesome-check --append stack.yml

faas up -f stack.yml --regex "my-awesome-check"
```
