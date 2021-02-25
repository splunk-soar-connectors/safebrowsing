# File: safebrowsing_consts.py
# Copyright (c) 2016-2021 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

SAFEBROWSING_BASE_URL = 'https://safebrowsing.googleapis.com/v4/'
SAFEBROWSING_API_KEY = 'key'
SAFEBROWSING_THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "POTENTIALLY_HARMFUL_APPLICATION", "UNWANTED_SOFTWARE", "MALICIOUS_BINARY"]
SAFEBROWSING_THREAT_ENTRY_TYPES = ["URL"]
SAFEBROWSING_PLATFORM_TYPES = ["ANY_PLATFORM"]
SAFEBROWSING_CLIENT_ID = 'phantomcyber'
SAFEBROWSING_CLIENT_VERSION = '1.0.0'

SAFEBROWSING_ERR_FROM_SERVER = "Got an unknown error from Google Safe Browsing server"
SAFEBROWSING_ERR_SERVER_CONNECTION = "Could not connect to Google Safe Browsing server"
