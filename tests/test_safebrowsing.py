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

from unittest.mock import MagicMock

import httpx
import pytest
from soar_sdk.exceptions import ActionFailure

from src import helpers
from src.actions.domain_reputation import DomainReputationParams, domain_reputation
from src.actions.url_reputation import UrlReputationParams, url_reputation
from src.asset import Asset

API_KEY = "test-api-key"  # pragma: allowlist secret


@pytest.fixture
def asset() -> Asset:
    return Asset.model_construct(key=API_KEY)


def _install_transport(monkeypatch, handler) -> dict:
    real_client = httpx.Client
    captured: dict = {}

    def factory(**kwargs):
        captured.update(kwargs)
        return real_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(helpers.httpx, "Client", factory)
    return captured


def test_api_key_sent_in_header_not_url(monkeypatch, asset):
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        seen["key"] = request.headers.get("X-Goog-Api-Key")
        return httpx.Response(200, json={"threatLists": [{"threatType": "MALWARE"}]})

    captured = _install_transport(monkeypatch, handler)
    result = helpers.make_rest_call(asset, "threatLists")

    assert result == {"threatLists": [{"threatType": "MALWARE"}]}
    assert seen["url"] == "https://safebrowsing.googleapis.com/v4/threatLists"
    assert seen["key"] == API_KEY
    assert API_KEY not in seen["url"]
    assert captured["verify"] is True
    assert captured["timeout"] == 30


def test_server_error_message_is_returned(monkeypatch, asset):
    _install_transport(
        monkeypatch,
        lambda request: httpx.Response(
            400, json={"error": {"message": "API key not valid."}}
        ),
    )
    with pytest.raises(ActionFailure) as exc:
        helpers.make_rest_call(asset, "threatLists")
    assert exc.value.message == "API key not valid."


def test_transport_error_does_not_leak_api_key(monkeypatch, asset):
    def handler(request):
        raise httpx.ConnectError(f"boom {API_KEY}", request=request)

    _install_transport(monkeypatch, handler)
    with pytest.raises(ActionFailure) as exc:
        helpers.make_rest_call(asset, "threatLists")
    assert exc.value.message == (
        "Could not connect to Google Safe Browsing server: ConnectError"
    )
    assert API_KEY not in exc.value.message


def test_reputation_no_matches(monkeypatch, asset):
    _install_transport(monkeypatch, lambda request: httpx.Response(200, json={}))
    soar = MagicMock()
    output = domain_reputation(DomainReputationParams(domain="splunk.com"), soar, asset)

    assert output.matches is None
    assert soar.set_summary.call_args.args[0].num_threat_matches == 0
    soar.set_message.assert_called_once_with(
        "Google Safe Browsing has no threat information about this domain"
    )


def test_reputation_with_matches(monkeypatch, asset):
    match = {
        "threatType": "MALWARE",
        "platformType": "ANY_PLATFORM",
        "threatEntryType": "URL",
        "threat": {"url": "http://malware.testing.google.test/testing/malware/"},
        "cacheDuration": "300s",
    }
    _install_transport(
        monkeypatch, lambda request: httpx.Response(200, json={"matches": [match]})
    )
    soar = MagicMock()
    output = url_reputation(
        UrlReputationParams(url=match["threat"]["url"]), soar, asset
    )

    assert output.matches[0].threatType == "MALWARE"
    assert soar.set_summary.call_args.args[0].num_threat_matches == 1
    soar.set_message.assert_called_once_with("Threat info retrieved successfully")
