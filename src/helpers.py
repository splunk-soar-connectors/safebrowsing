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

import os
import ssl
from pathlib import Path
from typing import Any

import httpx
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger

from .asset import Asset
from .safebrowsing_consts import (
    SAFEBROWSING_API_KEY_HEADER,
    SAFEBROWSING_BASE_URL,
    SAFEBROWSING_CLIENT_ID,
    SAFEBROWSING_CLIENT_VERSION,
    SAFEBROWSING_DEFAULT_TIMEOUT,
    SAFEBROWSING_EMPTY_PARAM,
    SAFEBROWSING_ERROR_CA_BUNDLE,
    SAFEBROWSING_ERROR_FROM_SERVER,
    SAFEBROWSING_ERROR_SERVER_CONNECTION,
    SAFEBROWSING_PLATFORM_TYPES,
    SAFEBROWSING_THREAT_ENTRY_TYPES,
    SAFEBROWSING_THREAT_MATCHES_ENDPOINT,
    SAFEBROWSING_THREAT_TYPES,
)

logger = getLogger()


def build_url(endpoint: str) -> str:
    return f"{SAFEBROWSING_BASE_URL}/{endpoint.lstrip('/')}"


def auth_headers(asset: Asset) -> dict[str, str]:
    """The API key always travels in a header, never in the URL (PAPP-38040)."""
    return {SAFEBROWSING_API_KEY_HEADER: asset.key}


def connection_error_message(error: Exception) -> str:
    """Only the exception type is reported, so credentials can never leak."""
    return f"{SAFEBROWSING_ERROR_SERVER_CONNECTION}: {type(error).__name__}"


def get_tls_verification(verify_ssl: bool = True) -> bool | ssl.SSLContext:
    """Honor the Requests CA bundle settings the legacy app relied on.

    HTTPX ignores REQUESTS_CA_BUNDLE and CURL_CA_BUNDLE, so deployments that trust
    a proxy CA through them would otherwise fail TLS verification after upgrading.
    """
    if not verify_ssl:
        return False
    ca_bundle = os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("CURL_CA_BUNDLE")
    if not ca_bundle:
        return True
    try:
        if Path(ca_bundle).is_dir():
            return ssl.create_default_context(capath=ca_bundle)
        return ssl.create_default_context(cafile=ca_bundle)
    except OSError as error:
        raise ActionFailure(SAFEBROWSING_ERROR_CA_BUNDLE) from error


def _server_error_message(resp_json: Any) -> str:
    if isinstance(resp_json, dict):
        error = resp_json.get("error")
        if isinstance(error, dict) and error.get("message"):
            return str(error["message"])
    return SAFEBROWSING_ERROR_FROM_SERVER


def make_rest_call(
    asset: Asset, endpoint: str, method: str = "GET", body: dict | None = None
) -> dict:
    try:
        with httpx.Client(
            verify=get_tls_verification(), timeout=SAFEBROWSING_DEFAULT_TIMEOUT
        ) as client:
            response = client.request(
                method, build_url(endpoint), headers=auth_headers(asset), json=body
            )
    except httpx.HTTPError as error:
        logger.debug(f"Safe Browsing request failed: {type(error).__name__}")
        raise ActionFailure(connection_error_message(error)) from None

    try:
        resp_json = response.json()
    except ValueError:
        resp_json = None

    if response.status_code != httpx.codes.OK:
        raise ActionFailure(_server_error_message(resp_json))
    if not isinstance(resp_json, dict):
        raise ActionFailure(SAFEBROWSING_ERROR_FROM_SERVER)
    return resp_json


def require_value(value: str, name: str) -> str:
    """Return the value without surrounding spaces; fail if nothing is left."""
    value = value.strip()
    if not value:
        raise ActionFailure(SAFEBROWSING_EMPTY_PARAM.format(name=name))
    return value


def lookup_threat_matches(asset: Asset, value: str) -> dict:
    """Ask Google Safe Browsing for threat matches on a URL or domain."""
    body = {
        "client": {
            "clientId": SAFEBROWSING_CLIENT_ID,
            "clientVersion": SAFEBROWSING_CLIENT_VERSION,
        },
        "threatInfo": {
            "threatTypes": SAFEBROWSING_THREAT_TYPES,
            "platformTypes": SAFEBROWSING_PLATFORM_TYPES,
            "threatEntryTypes": SAFEBROWSING_THREAT_ENTRY_TYPES,
            "threatEntries": [{"url": value}],
        },
    }
    return make_rest_call(
        asset, SAFEBROWSING_THREAT_MATCHES_ENDPOINT, method="POST", body=body
    )
