#!/bin/bash

# to run this setup credentials & repo/artifact info (see below) as env variables
# install jfrog cli and docker runtime
# install jq (if mac then run 'brew install jq')

# credentials
export JF_PLATFORM_URL="https://soleng.jfrog.io"
export JF_PLATFORM_PORT=443
export JF_TOKEN_USER="${JF_TOKEN_USER:-'NoUserSet'}"
export JF_ACCESS_TOKEN="${JF_ACCESS_TOKEN:-'NoAccessTokenSet'}"
export JF_REFERENCE_TOKEN="${JF_REFERENCE_TOKEN:-'NoReferenceTokenSet'}"

# echo credentials
# echo "URL: ${JF_PLATFORM_URL}"
# echo "USER: ${JF_TOKEN_USER}"
# echo "PORT: ${JF_PLATFORM_PORT}"
# echo "TOKEN: ${JF_ACCESS_TOKEN}"

# Check Prerequisites....

# Check if jfrog cli is installed
if ! command -v jf >/dev/null 2>&1; then
    echo "jf is not installed. Exiting. Please install the JFrog CLI using your package manager (ex: https://jfrog.com/getcli/)"
    exit 1
fi

# Check if curl is installed
if ! command -v curl >/dev/null 2>&1; then
    echo "curl is not installed. Exiting."
    exit 1
fi

# Check if jq is installed
if ! command -v jq >/dev/null 2>&1; then
    echo "jq is not installed. Exiting. Please install jq with your package manager (ex: 'brew install jq')"
    exit 1
fi

# Check if Docker daemon is running
if ! docker info >/dev/null 2>&1; then
    echo "Docker daemon is not running. Exiting."
    exit 1
fi

# configure JFrog CLI with a default profile
export JFROG_SERVICE_ID="solengserver"
jf c rm "${JFROG_SERVICE_ID}" --quiet
jf c add "${JFROG_SERVICE_ID}" --url="${JF_PLATFORM_URL}" --access-token="${JF_ACCESS_TOKEN}" --interactive=false
jf c use "${JFROG_SERVICE_ID}"

# test connection to get a OK
# curl -XGET "${JF_PLATFORM_URL}:${JF_PLATFORM_PORT}/artifactory/api/system/ping" \
#   -H "Content-Type: text/plain" \
#   -H "Authorization: Bearer ${JF_REFERENCE_TOKEN}"

# Check if JFrog CLI command "jf rt ping" is successful
if ! jf rt ping >/dev/null 2>&1; then
    echo "JFrog ping was not successful. Check your server URL and access tokens."
    exit 1
fi

# repo name (assumes repo exists)
export REPO_NAME="boaz-docker-local"
export ARTIFACT_ORG="webgoat"
export ARTIFACT_NAME="webgoat"
export ARTIFACT_TAG="latest"
export ARTIFACT_NAME_TAG="${ARTIFACT_NAME}:${ARTIFACT_TAG}"

# echo repo & artifact
# echo "REPO: ${REPO_NAME}"
# echo "ARTIFACT ORG: ${ARTIFACT_ORG}"
# echo "ARTIFACT NAME: ${ARTIFACT_NAME}"
# echo "ARTIFACT TAG: ${ARTIFACT_TAG}"
# echo "ARTIFACT NAME TAG: ${ARTIFACT_NAME_TAG}"

# enable repo indexing
# curl -XGET "${JF_PLATFORM_URL}:${JF_PLATFORM_PORT}/artifactory/api/repositories/${REPO_NAME}" \
#   -H "Content-Type: application/json" \
#   -H "Authorization: Bearer ${JF_REFERENCE_TOKEN}"

curl -XPOST "${JF_PLATFORM_URL}:${JF_PLATFORM_PORT}/artifactory/api/repositories/${REPO_NAME}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JF_REFERENCE_TOKEN}" \
  -d '{ 
    "LOCAL": [
      {
        "xrayIndex": true
      }
    ]
  }'

# configure repo for scan

# curl -XGET "${JF_PLATFORM_URL}:${JF_PLATFORM_PORT}/xray/api/v1/repos_config/${REPO_NAME}" \
#   -H "Content-Type: application/json" \
#   -H "Authorization: Bearer ${JF_REFERENCE_TOKEN}" 

curl -XPUT "${JF_PLATFORM_URL}:${JF_PLATFORM_PORT}/xray/api/v1/repos_config" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JF_REFERENCE_TOKEN}" \
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

# # prep a sample docker image to scan (assumes docker runtime is running)
docker pull ${ARTIFACT_ORG}/${ARTIFACT_NAME_TAG}

# # upload the webgoat (assumes boaz-docker-local exists)
docker login -u ${JF_TOKEN_USER} -p ${JF_REFERENCE_TOKEN} ${JF_PLATFORM_URL}
docker tag webgoat/webgoat:latest ${JF_PLATFORM_URL:8}/${REPO_NAME}/${ARTIFACT_NAME_TAG}
docker push ${JF_PLATFORM_URL:8}/${REPO_NAME}/${ARTIFACT_NAME_TAG}

# # wait for the scan to complete (need a better solution)
sha1=$(curl -XGET "${JF_PLATFORM_URL}:${JF_PLATFORM_PORT}/artifactory/api/storage/${REPO_NAME}/${ARTIFACT_NAME}/${ARTIFACT_TAG}/manifest.json" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JF_REFERENCE_TOKEN}" | jq -r '.checksums.sha1')
sha256=$(curl -XGET "${JF_PLATFORM_URL}:${JF_PLATFORM_PORT}/artifactory/api/storage/${REPO_NAME}/${ARTIFACT_NAME}/${ARTIFACT_TAG}/manifest.json" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JF_REFERENCE_TOKEN}" | jq -r '.checksums.sha256')
wait=1
isDone="unknown"
while [ "${isDone}" != "scanned" ]
do
  echo "Waiting ${wait} times..."
  wait=$(( $wait + 1 ))
  sleep 10
  isDone=$(curl -XPOST "${JF_PLATFORM_URL}:${JF_PLATFORM_PORT}/xray/api/v1/scan/status/artifact" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${JF_REFERENCE_TOKEN}" \
    -d '{
    "repository_pkg_type": "Docker",
    "path": '\"${REPO_NAME}/${ARTIFACT_NAME}/${ARTIFACT_TAG}/manifest.json\"',
    "sha256": '\"${sha256}\"',
    "sha1": '\"${sha1}\"'
    }' | jq -r '.status')
  echo "Scan completed? ${isDone}"
  if [ ${wait} -gt 60 ]
  then
    echo "Waited loooong.... breaking!"
    break
  fi
done

# download SBOM (CycloneDX with VEX)
if [ "${isDone}" == "scanned" ]
then
  curl -XPOST "${JF_PLATFORM_URL}:${JF_PLATFORM_PORT}/xray/api/v2/component/exportDetails" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${JF_REFERENCE_TOKEN}" \
    -d '{
    "package_type": "docker",
    "component_name": '"\"${ARTIFACT_NAME_TAG}\""',
    "path": '"\"${REPO_NAME}"/"${ARTIFACT_NAME}"/"${ARTIFACT_TAG}"/manifest.json\"',
    "cyclonedx": true,
    "cyclonedx_format": "json",
    "vex": true
    }' \
    -o "${ARTIFACT_NAME}".zip
fi
