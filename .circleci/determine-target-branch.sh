#!/bin/bash

# The intent of this script, when invoked by CircleCI is to mimic the behavior
# the TRAVIS_BRANCH environment variable to determine the target branch of
# the build.
#
# Namely, it is set to a value according to the following rules:
# - for push builds, or builds not triggered by a pull request, this is the name of the branch.
# - for builds triggered by a pull request this is the name of the branch targeted by the pull request.
# - for builds triggered by a tag, this is the same as the name of the tag (CIRCLECI_TAG).

if [ -n "${CIRCLE_PR_NUMBER}" ]; then
    curl -s https://api.github.com/repos/${CIRCLE_PROJECT_USERNAME}/${CIRCLE_PROJECT_REPONAME}/pulls/${CIRCLE_PR_NUMBER} | jq -r '.base.ref'
elif [ -n "${CIRCLE_TAG}" ]; then
    echo "${CIRCLE_TAG}"
else
    echo "${CIRCLE_BRANCH}"
fi
