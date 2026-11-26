# Copyright (c) 2016-2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

SAFEBROWSING_BASE_URL = "https://safebrowsing.googleapis.com/v4"
SAFEBROWSING_API_KEY_HEADER = "X-Goog-Api-Key"  # pragma: allowlist secret
SAFEBROWSING_DEFAULT_TIMEOUT = 30

SAFEBROWSING_THREAT_LISTS_ENDPOINT = "threatLists"
SAFEBROWSING_THREAT_MATCHES_ENDPOINT = "threatMatches:find"

SAFEBROWSING_CLIENT_ID = "phantomcyber"
SAFEBROWSING_CLIENT_VERSION = "1.0.0"
SAFEBROWSING_THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "POTENTIALLY_HARMFUL_APPLICATION",
    "UNWANTED_SOFTWARE",
    "MALICIOUS_BINARY",
]
SAFEBROWSING_PLATFORM_TYPES = ["ANY_PLATFORM"]
SAFEBROWSING_THREAT_ENTRY_TYPES = ["URL"]

SAFEBROWSING_TEST_CONNECTIVITY_PROGRESS = "Checking API Key with Google Safe Browsing"
SAFEBROWSING_TEST_CONNECTIVITY_PASSED = "Test Connectivity Passed"
SAFEBROWSING_THREAT_INFO_RETRIEVED = "Threat info retrieved successfully"
SAFEBROWSING_NO_THREAT_INFO = (
    "Google Safe Browsing has no threat information about this {entity}"
)

SAFEBROWSING_ERROR_FROM_SERVER = (
    "Got an unknown error from the Google Safe Browsing server"
)
SAFEBROWSING_ERROR_SERVER_CONNECTION = (
    "Could not connect to Google Safe Browsing server"
)
SAFEBROWSING_EMPTY_PARAM = "The '{name}' parameter cannot be empty"
SAFEBROWSING_ERROR_CA_BUNDLE = "Unable to load the configured CA trust bundle"
