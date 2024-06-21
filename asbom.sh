#!/bin/bash

# credentials
export JF_PLATFORM_URL="https://soleng.jfrog.io"
export JF_PLATFORM_PORT=443
export JF_ACCESS_TOKEN="${JF_ACCESS_TOKEN:-'NoAccessTokenSet'}"

# echo credentials (for test, to be removed later)
echo "URL: ${JF_PLATFORM_URL}"
echo "TOKEN: ${JF_ACCESS_TOKEN}"

# configure JFrog CLI with a default profile
export JFROG_SERVICE_ID="solengserver"
jf c rm "${JFROG_SERVICE_ID}" --quiet
jf c add "${JFROG_SERVICE_ID}" --url="${JF_PLATFORM_URL}" --access-token="${JF_ACCESS_TOKEN}" --interactive=false
jf c use "${JFROG_SERVICE_ID}"

# test connection to get a OK
jf rt ping

# repo name (assumes repo exists)
export REPO_NAME="boaz-docker-local"

#curl -XGET "${JF_PLATFORM_URL}:${JF_PLATFORM_PORT}/xray/api/v1/repos_config/boaz-docker-local" \
#  -H "Content-Type: application/json" \
#  -H "Authorization: Bearer ${JF_ACCESS_TOKEN}" 


# configure repo for scan
curl -XPUT "${JF_PLATFORM_URL}:${JF_PLATFORM_PORT}/xray/api/v1/repos_config" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JF_ACCESS_TOKEN}" \
  -d \
"{ \
  "repo_name": "${REPO_NAME}", \
  "repo_config": { \
    "vuln_contextual_analysis": true, \
    "exposures": { \
      "scanners_category": { \
        "services_scan": true, \
        "secrets_scan": true, \
        "applications_scan": true \
      } \
    }, \
    "retention_in_days": 30 \
  },\
  "other_artifacts": { \
    "index_new_artifacts": true, \
    "retention_in_days": 30 \
  } \
}"


exit 0

# prep a sample docker image to scan (assumes docker runtime is running)
docker pull webgoat/webgoat:latest

# upload the webgoat (assumes boaz-docker-local exists & indexed)
jf rt u webgoat/webgoat $REPO_NAME

# wait for the scan to complete (need a better solution)
sleep 300s

# download SBOM (CycloneDX with VEX)
curl -XPOST "${JF_PLATFORM_URL}//xray/api/v2/component/exportDetails" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JF_ACCESS_TOKEN}" \
  -d @- << EOF
{
  "package_type": "docker",
  "component_name": "webgoat:latest",
  "path": "${REPO_NAME}/webgoat/latest/manifest.json",
  "violations": true,
  "include_ignored_violations": true,
  "license": true,
  "exclude_unknown": true,
  "operational_risk": true,
  "security": true,
  "secrets": true,
  "services": true,
  "applications": true,
  "output_format": "pdf"
  "cyclonedx": true,
  "cyclonedx_format": "json",
  "vex": true
}
EOF