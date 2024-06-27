#!/bin/bash

###################################################
# This script is used to download SBOM report
#					
# Author:	Selva Sabapathy 
#
###################################################

##############
# Description:
##############
echo
echo "======================================================="
echo "This script will push a docker image to Artifactory"
echo "Do a Xray scan and downloads SBOM reports"
echo "======================================================="
echo
sleep 1

## Pre-requesties check 

# jq check
echo "Checking if JQ was installed..."
if ! command -v jq &> /dev/null
then
    echo "JQ could not be found"
    exit 1
else 
  echo "JQ exists"
fi

# credentials
echo ""
echo "Enter you Artifactory URL (eg: hts1.jfrog.io): "
read JF_URL
export JF_PLATFORM_URL=https://${JF_URL}
echo $JF_PLATFORM_URL
# export JF_PLATFORM_URL="https://soleng.jfrog.io"
# export JF_PLATFORM_PORT=443
echo ""
echo "Enter username: "
read JF_TOKEN_USER
export JF_TOKEN_USER

echo ""
echo "Enter Token: "
read JF_ACCESS_TOKEN
export JF_ACCESS_TOKEN
# export JF_REFERENCE_TOKEN=${JF_ACCESS_TOKEN}

echo ""
echo "Enter repo name: "
read REPO_NAME
export REPO_NAME
export ARTIFACT_ORG="webgoat"
export ARTIFACT_NAME="webgoat"
export ARTIFACT_TAG="latest"
export ARTIFACT_NAME_TAG="${ARTIFACT_NAME}:${ARTIFACT_TAG}"

echo ""
echo "-------------------------------------"
echo "URL: ${JF_PLATFORM_URL}"
echo "USER: ${JF_TOKEN_USER}"
# echo "PORT: ${JF_PLATFORM_PORT}"
# echo "TOKEN: ${JF_ACCESS_TOKEN}"
echo "REPO: ${REPO_NAME}"
# echo "ARTIFACT ORG: ${ARTIFACT_ORG}"
# echo "ARTIFACT NAME: ${ARTIFACT_NAME}"
# echo "ARTIFACT TAG: ${ARTIFACT_TAG}"
# echo "ARTIFACT NAME TAG: ${ARTIFACT_NAME_TAG}"
echo "-------------------------------------"
echo ""
# enable repo indexing
# curl -XGET "${JF_PLATFORM_URL}:${JF_PLATFORM_PORT}/artifactory/api/repositories/${REPO_NAME}" \
#   -H "Content-Type: application/json" \
#   -H "Authorization: Bearer ${JF_REFERENCE_TOKEN}"
echo "-------------------------------------"
echo "Enabling Xray for ${REPO_NAME} repo"
echo "-------------------------------------"
curl -XPOST "${JF_PLATFORM_URL}/artifactory/api/repositories/${REPO_NAME}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JF_ACCESS_TOKEN}" \
  -d '{ 
    "LOCAL": [
      {
        "xrayIndex": true
      }
    ]
  }'

if [ $? -eq 0 ]; then
    echo ""
else
    echo "Previous command was unsuccessful"
    exit 1
fi

# configure repo for scan

# curl -XGET "${JF_PLATFORM_URL}:${JF_PLATFORM_PORT}/xray/api/v1/repos_config/${REPO_NAME}" \
#   -H "Content-Type: application/json" \
#   -H "Authorization: Bearer ${JF_REFERENCE_TOKEN}" 

curl -XPUT "${JF_PLATFORM_URL}/xray/api/v1/repos_config" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JF_ACCESS_TOKEN}" \
  -d '{ 
  "repo_name": '"\"${REPO_NAME}\""', 
  "repo_config": { 
    "vuln_contextual_analysis": true,
    "exposures": { 
      "scanners_category": { 
        "services_scan": true, 
        "secrets_scan": true, 
        "applications_scan": true 
      } 
    }, 
    "retention_in_days": 30 
  } 
}'
if [ $? -eq 0 ]; then
    echo ""
else
    echo "Previous command was unsuccessful"
    exit 1
fi
# # prep a sample docker image to scan (assumes docker runtime is running)
echo ""
echo "Executing \"docker pull $ARTIFACT_ORG/$ARTIFACT_NAME_TAG\""
docker pull ${ARTIFACT_ORG}/${ARTIFACT_NAME_TAG}

# # upload the webgoat (assumes boaz-docker-local exists)
# docker login -u ${JF_TOKEN_USER} -p ${JF_REFERENCE_TOKEN} ${JF_PLATFORM_URL}
export DOCKER_DOMAIN=$(echo "${JF_URL}" | sed 's/.jfrog.io/'"-${REPO_NAME}"'&/')
echo $JF_ACCESS_TOKEN | docker login -u ${JF_TOKEN_USER} --password-stdin ${DOCKER_DOMAIN}
docker tag webgoat/webgoat:latest ${DOCKER_DOMAIN}/${ARTIFACT_NAME_TAG}

echo ""
echo "Pushing docker image to Artifactory"
docker push ${DOCKER_DOMAIN}/${ARTIFACT_NAME_TAG}

echo ""
# # wait for the scan to complete (need a better solution)
sha1=$(curl -sS -XGET "${JF_PLATFORM_URL}/artifactory/api/storage/${REPO_NAME}/${ARTIFACT_NAME}/${ARTIFACT_TAG}/manifest.json" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JF_ACCESS_TOKEN}" | jq -r '.checksums.sha1')
sha256=$(curl -sS -XGET "${JF_PLATFORM_URL}/artifactory/api/storage/${REPO_NAME}/${ARTIFACT_NAME}/${ARTIFACT_TAG}/manifest.json" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JF_ACCESS_TOKEN}" | jq -r '.checksums.sha256')
wait=1
isDone="unknown"
while [ "${isDone}" != "scanned" ]
do
  echo "Waiting ${wait} times..."
  echo ""
  wait=$(( $wait + 1 ))
  sleep 10
  isDone=$(curl -sS -XPOST "${JF_PLATFORM_URL}/xray/api/v1/scan/status/artifact" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${JF_ACCESS_TOKEN}" \
    -d '{
    "repository_pkg_type": "Docker",
    "path": '\"${REPO_NAME}/${ARTIFACT_NAME}/${ARTIFACT_TAG}/manifest.json\"',
    "sha256": '\"${sha256}\"',
    "sha1": '\"${sha1}\"'
    }' | jq -r '.status')
  echo "Scan status is ${isDone}"
  if [ ${wait} -gt 60 ]
  then
    echo "Waited loooong.... breaking!"
    break
  fi
done

# download SBOM (CycloneDX with VEX)
if [ "${isDone}" == "scanned" ]
then
  echo ""
  echo "Downloading SBOM (CycloneDX) of ${ARTIFACT_NAME}"
  curl -sS -XPOST "${JF_PLATFORM_URL}/xray/api/v2/component/exportDetails" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${JF_ACCESS_TOKEN}" \
    -d '{
    "package_type": "docker",
    "component_name": '"\"${ARTIFACT_NAME_TAG}\""',
    "path": '"\"${REPO_NAME}"/"${ARTIFACT_NAME}"/"${ARTIFACT_TAG}"/manifest.json\"',
    "violations": true,
    "include_ignored_violations": true,
    "license": true,
    "exclude_unknown": true,
    "vulnerabilities": true,
    "operational_risk": true,
    "secrets": true,
    "services": true,
    "applications": true,
    "output_format": "pdf",
    "cyclonedx": true,
    "cyclonedx_format": "json",
    "vex": true
    }' \
    -o "${ARTIFACT_NAME}".zip
  echo ""
  echo "Download Completed!"
fi