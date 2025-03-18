# File: safebrowsing_consts.py
#
# Copyright (c) 2016-2025 Splunk Inc.
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
SAFEBROWSING_BASE_URL = "https://safebrowsing.googleapis.com/v4/"
SAFEBROWSING_API_KEY = "key"  # pragma: allowlist secret
SAFEBROWSING_THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "POTENTIALLY_HARMFUL_APPLICATION", "UNWANTED_SOFTWARE", "MALICIOUS_BINARY"]
SAFEBROWSING_THREAT_ENTRY_TYPES = ["URL"]
SAFEBROWSING_PLATFORM_TYPES = ["ANY_PLATFORM"]
SAFEBROWSING_CLIENT_ID = "phantomcyber"
SAFEBROWSING_CLIENT_VERSION = "1.0.0"

SAFEBROWSING_ERR_FROM_SERVER = "Got an unknown error from the Google Safe Browsing server"
SAFEBROWSING_ERR_SERVER_CONNECTION = "Could not connect to Google Safe Browsing server"
