#!/usr/bin/env bash
set -euo pipefail

curl-with-retry() {
    curl --fail --silent --show-error --retry 5 --retry-all-errors --retry-max-time 120 "$@"
}

# Unauthenticated GitHub API requests share a low rate limit per source IP,
# and hosted runners share IPs, so the lookup below gets throttled at times.
# Authenticating with the workflow token lifts that limit. The function takes
# an API path rather than a URL so the token can only be sent to the GitHub
# API, never to Docker Hub.
github-api() {
    local url="https://api.github.com/$1"
    if [[ -n "${GH_TOKEN:-}" ]]; then
        curl-with-retry -H "Authorization: Bearer ${GH_TOKEN}" "$url"
    else
        curl-with-retry "$url"
    fi
}

kind_release_info=$(github-api repos/kubernetes-sigs/kind/releases/latest)
kind_version=$(echo "$kind_release_info" | jq -r '.tag_name // empty')
if [[ ! "$kind_version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "unable to determine the latest kind version, got \"$kind_version\" from: $kind_release_info" >&2
    exit 1
fi

all_tags=()
# Currently we're taking the first 5 pages of the URL
for ((page = 1; page <= 5; page++)); do
    # Fetch tags for the current page using curl and jq
    tags=$(curl-with-retry "https://hub.docker.com/v2/repositories/kindest/node/tags?page=$page" | jq -r '.results[].name')

    # Check if the tags variable is empty
    if [[ -z "$tags" ]]; then
        break
    fi

    # Append the current page tags to the all_tags array
    all_tags+=("$tags")
done

readarray -t tags_sorted < <(printf '%s\n' "${all_tags[@]}" | sort -V)

lowest_target_version=$(cat ./test/integration/suites/k8s/integration_k8s_min_version.txt)

declare -A tags_map=()
for element in "${tags_sorted[@]}"; do
    # Only consider release tags in the form "vX.YY.ZZ"
    if [[ ! "$element" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        continue
    fi

    # Extract the "vX.YY" part as the key for the map
    key="${element%.*}"
    # Check if the key is greater than or equal to the lowest target version
    if [[ $(printf "%s\n$lowest_target_version" "$key" | sort -V | head -n1) == "$lowest_target_version" ]]; then
        # Extract the "ZZ" part as the value for the map
        value="${element##*.}"
        tags_map["$key"]=$value
    fi
done

if [[ ${#tags_map[@]} -eq 0 ]]; then
    echo "no kindest/node tags at or above $lowest_target_version were found in: ${tags_sorted[*]}" >&2
    exit 1
fi

# Read the content of the array.txt file
# Currently we just have one row as example, add more if we need to test a specific version
# Test elements should be added as [KubeCTLVersion, K8s-image, KindVersion]
IFS= readarray -t matrix_lines <./test/integration/suites/k8s/integration_k8s_versions.txt

# Convert each line of the file into a JSON array element
json_array="["
for line in "${matrix_lines[@]}"; do
    json_array+="$line,"
done

# Add every version from tags_map
for key in "${!tags_map[@]}"; do
    value="${tags_map[$key]}"
    k8s_image="kindest/node:$key.$value"
    new_version_row="[\"$key.$value\",\"$k8s_image\",\"$kind_version\"]"
    json_array+="$new_version_row,"
done

json_array="${json_array%,}]"

# Fail here rather than in every k8s job if the matrix is not valid JSON
echo "${json_array}" | jq -c .
