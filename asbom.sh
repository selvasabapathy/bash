#!/bin/bash

# credentials
export JF_PLATFORM_URL="https://soleng.jfrog.io"
export JF_PLATFORM_PORT=443
export JF_ACCESS_TOKEN="${JF_ACCESS_TOKEN:-'NoAccessTokenSet'}"
export JF_REFERENCE_TOKEN="${JF_REFERENCE_TOKEN:-'NoReferenceTokenSet'}"

# echo credentials (for test, to be removed later)
# echo "URL: ${JF_PLATFORM_URL}"
# echo "PORT: ${JF_PLATFORM_PORT}"
# echo "TOKEN: ${JF_ACCESS_TOKEN}"

# configure JFrog CLI with a default profile
export JFROG_SERVICE_ID="solengserver"
jf c rm "${JFROG_SERVICE_ID}" --quiet
jf c add "${JFROG_SERVICE_ID}" --url="${JF_PLATFORM_URL}" --access-token="${JF_ACCESS_TOKEN}" --interactive=false
jf c use "${JFROG_SERVICE_ID}"

# test connection to get a OK
# curl -XGET "${JF_PLATFORM_URL}:${JF_PLATFORM_PORT}/artifactory/api/system/ping" \
#   -H "Content-Type: text/plain" \
#   -H "Authorization: Bearer ${JF_REFERENCE_TOKEN}"
jf rt ping

# repo name (assumes repo exists)
export REPO_NAME="boaz-docker-local"

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

curl -XGET "${JF_PLATFORM_URL}:${JF_PLATFORM_PORT}/artifactory/api/repositories/${REPO_NAME}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JF_REFERENCE_TOKEN}"

exit 0

# configure repo for scan

# curl -XGET "${JF_PLATFORM_URL}:${JF_PLATFORM_PORT}/xray/api/v1/repos_config/${REPO_NAME}" \
#   -H "Content-Type: application/json" \
#   -H "Authorization: Bearer ${JF_ACCESS_TOKEN}" 

# curl -XPUT "${JF_PLATFORM_URL}:${JF_PLATFORM_PORT}/xray/api/v1/repos_config" \
#   -H "Content-Type: application/json" \
#   -H "Authorization: Bearer ${JF_ACCESS_TOKEN}" \
#   -d '{ 
#   "repo_name": "${REPO_NAME}", 
#   "repo_config": { 
#     "vuln_contextual_analysis": true,
#     "exposures": { 
#       "scanners_category": { 
#         "services_scan": true, 
#         "secrets_scan": true, 
#         "applications_scan": true 
#       } 
#     }, 
#     "retention_in_days": 30 
#   } 
# }'


# exit 0

# # prep a sample docker image to scan (assumes docker runtime is running)
# docker pull webgoat/webgoat:latest

# # upload the webgoat (assumes boaz-docker-local exists & indexed)
# jf rt u webgoat/webgoat $REPO_NAME

# # wait for the scan to complete (need a better solution)
# sleep 300s

# # download SBOM (CycloneDX with VEX)
# curl -XPOST "${JF_PLATFORM_URL}//xray/api/v2/component/exportDetails" \
#   -H "Content-Type: application/json" \
#   -H "Authorization: Bearer ${JF_ACCESS_TOKEN}" \
#   -d @- << EOF
# {
#   "package_type": "docker",
#   "component_name": "webgoat:latest",
#   "path": "${REPO_NAME}/webgoat/latest/manifest.json",
#   "violations": true,
#   "include_ignored_violations": true,
#   "license": true,
#   "exclude_unknown": true,
#   "operational_risk": true,
#   "security": true,
#   "secrets": true,
#   "services": true,
#   "applications": true,
#   "output_format": "pdf"
#   "cyclonedx": true,
#   "cyclonedx_format": "json",
#   "vex": true
# }
# EOF