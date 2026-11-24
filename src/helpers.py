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

from typing import Any

import httpx
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger

from .asset import Asset
from .safebrowsing_consts import (
    SAFEBROWSING_API_KEY_HEADER,
    SAFEBROWSING_BASE_URL,
    SAFEBROWSING_DEFAULT_TIMEOUT,
    SAFEBROWSING_ERROR_FROM_SERVER,
    SAFEBROWSING_ERROR_SERVER_CONNECTION,
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
        with httpx.Client(verify=True, timeout=SAFEBROWSING_DEFAULT_TIMEOUT) as client:
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
