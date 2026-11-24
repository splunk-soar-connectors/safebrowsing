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

import json

import httpx
from soar_sdk.action_results import MakeRequestOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import MakeRequestParams, Param

from ..asset import Asset
from ..helpers import auth_headers, build_url, connection_error_message
from ..safebrowsing_consts import (
    SAFEBROWSING_API_KEY_HEADER,
    SAFEBROWSING_BASE_URL,
    SAFEBROWSING_DEFAULT_TIMEOUT,
)


class SafeBrowsingMakeRequestParams(MakeRequestParams):
    endpoint: str = Param(
        description=(
            "Google Safe Browsing API endpoint to call, appended to the base URL "
            f"({SAFEBROWSING_BASE_URL}). Do not include the base URL. "
            "Example: '/threatLists'"
        ),
        required=True,
    )


def _parse_json(value: str, name: str) -> object:
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError) as e:
        raise ActionFailure(f"The '{name}' parameter must be valid JSON") from e


def http_action(
    params: SafeBrowsingMakeRequestParams, asset: Asset
) -> MakeRequestOutput:
    """Make an authenticated request to the Google Safe Browsing API."""
    if params.endpoint.startswith(("http://", "https://")):
        raise ActionFailure(
            f"Invalid endpoint: {params.endpoint}. Do not include the base URL."
        )
    url = build_url(params.endpoint)

    headers: dict[str, str] = {}
    if params.headers:
        user_headers = _parse_json(params.headers, "headers")
        if not isinstance(user_headers, dict):
            raise ActionFailure("The 'headers' parameter must be a JSON object")
        headers = {
            str(name): str(value)
            for name, value in user_headers.items()
            if str(name).lower() != SAFEBROWSING_API_KEY_HEADER.lower()
        }
    headers.update(auth_headers(asset))

    query_params = None
    if params.query_parameters:
        try:
            parsed = json.loads(params.query_parameters)
        except (json.JSONDecodeError, TypeError):
            query_string = params.query_parameters.split("#", 1)[0].lstrip("?")
            url = f"{url}{'&' if '?' in url else '?'}{query_string}"
        else:
            if not isinstance(parsed, dict):
                raise ActionFailure(
                    "The 'query_parameters' parameter must be a JSON object "
                    "or a raw query string"
                )
            query_params = parsed

    body = _parse_json(params.body, "body") if params.body else None

    try:
        with httpx.Client(verify=params.verify_ssl) as client:
            response = client.request(
                params.http_method,
                url,
                headers=headers,
                params=query_params,
                json=body,
                timeout=params.timeout or SAFEBROWSING_DEFAULT_TIMEOUT,
            )
    except (httpx.HTTPError, httpx.InvalidURL, ValueError) as error:
        raise ActionFailure(connection_error_message(error)) from None

    return MakeRequestOutput(
        status_code=response.status_code, response_body=response.text
    )
