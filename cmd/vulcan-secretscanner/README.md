# Dev info

We use:

- `skopeo` just to download the images from the registry without root or docker daemon access.
- `SecretScanner` go get from from git repo.
- `hyperscan` is the Intel Hyperscan library used by SecretScanner.

```sh
docker build . -t vss

# Scan public image
docker run -it --rm -e TARGET=docker.io/library/alpine:latest vss

# Scan private image
docker run -it --rm -e REGISTRY_USERNAME=$REGISTRY_USERNAME -e REGISTRY_PASSWORD=$REGISTRY_PWD -e REGISTRY_DOMAIN=private.registry -e TARGET=private.registry/library/node:8 vss
```
