#!/usr/bin/env bash

curl-with-retry() {
    curl --retry 5 --retry-all-errors --retry-max-time 120 "$@"
}

kind_release_info=$(curl-with-retry -s https://api.github.com/repos/kubernetes-sigs/kind/releases/latest)
kind_version=$(echo "$kind_release_info" | jq -r '.tag_name')

all_tags=()
# Currently we're taking the first 5 pages of the URL
for ((page = 1; page <= 5; page++)); do
    # Fetch tags for the current page using curl and jq
    tags=$(curl-with-retry -s "https://hub.docker.com/v2/repositories/kindest/node/tags?page=$page" | jq -r '.results[].name')

    # Check if the tags variable is empty
    if [[ -z "$tags" ]]; then
        break
    fi

    # Append the current page tags to the all_tags array
    all_tags+=("$tags")
done

readarray -t tags_sorted < <(printf '%s\n' "${all_tags[@]}" | sort -V)

lowest_target_version=$(cat ./test/integration/suites/k8s/integration_k8s_min_version.txt)

declare -A tags_map
for element in "${tags_sorted[@]}"; do
    # Element is in this form: "X.XX.YY"
    # If not, continue
    num_dots=$(echo "$element" | grep -o '\.' | wc -l)

    # Continue to the next iteration if the number of dots is not equal to 2
    if [[ "$num_dots" -ne 2 ]]; then
        continue
    fi

    # Extract the "X.XX" part as the key for the map
    key="${element%.*}"
    key="${key//\"/}"
    # Check if the key is greater than or equal to "1.21"
    if [[ $(printf "%s\n$lowest_target_version" "$key" | sort -V | head -n1) == "$lowest_target_version" ]]; then
        # Extract the "YY" part as the value for the map
        value="${element##*.}"
        tags_map["$key"]=$value
    fi
done

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

echo "${json_array}"
