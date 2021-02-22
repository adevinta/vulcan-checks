#!/bin/bash

IMAGE=${TARGET:-'docker.io/library/alpine:latest'}

mkdir -p /work/img

MANIFEST=/work/img/manifest.json

if [[ -n $REGISTRY_DOMAIN ]] && [[ $IMAGE == $REGISTRY_DOMAIN* ]] ;
then
    skopeo copy --src-creds $REGISTRY_USERNAME:$REGISTRY_PASSWORD docker://$IMAGE dir:/work/img
else
    skopeo copy docker://$IMAGE dir:/work/img
fi

if [[ $? != 0 ]] || [[ ! -f $MANIFEST ]];
then
    echo "Unable to get image manifest"
    exit -1
fi

case $(cat $MANIFEST | jq -r '.schemaVersion') in
1)
    LAYERS=$( cat $MANIFEST | jq -r '.fsLayers[].blobSum|split(":")[1]' | tac )
;;
2)
    LAYERS=$( cat $MANIFEST | jq -r '.layers[].digest|split(":")[1]' )
;;
  *)
    echo "Unable to get a valid schemaVersion"
    exit -1
;;
esac

mkdir /work/out
for layer in $LAYERS
do
    tar xf /work/img/$layer -C /work/out
done

mkdir /work/res

/ss/SecretScanner -local /work/out/ -output-path /work/res
