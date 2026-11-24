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

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..helpers import make_rest_call
from ..safebrowsing_consts import (
    SAFEBROWSING_CLIENT_ID,
    SAFEBROWSING_CLIENT_VERSION,
    SAFEBROWSING_NO_THREAT_INFO,
    SAFEBROWSING_PLATFORM_TYPES,
    SAFEBROWSING_THREAT_ENTRY_TYPES,
    SAFEBROWSING_THREAT_INFO_RETRIEVED,
    SAFEBROWSING_THREAT_MATCHES_ENDPOINT,
    SAFEBROWSING_THREAT_TYPES,
)

logger = getLogger()


class UrlReputationParams(Params):
    url: str = Param(
        description="Determines the URL reputation",
        primary=True,
        cef_types=["url", "domain"],
        column_name="URL",
    )


class UrlThreatOutput(ActionOutput):
    url: str | None = OutputField(
        cef_types=["url", "domain"], example_values=["https://www.test.com"]
    )


class UrlThreatMatchOutput(PermissiveActionOutput):
    # Permissive: Google may add match fields (e.g. threatEntryMetadata) that the
    # legacy app stored as-is.
    threatType: str | None = OutputField(column_name="Threat Type")
    platformType: str | None = OutputField(column_name="Platform Type")
    threatEntryType: str | None = OutputField(column_name="Threat Entry Type")
    threat: UrlThreatOutput | None = None
    cacheDuration: str | None = None


class UrlReputationOutput(ActionOutput):
    matches: list[UrlThreatMatchOutput] | None = None


class UrlReputationSummary(ActionOutput):
    num_threat_matches: int | None = None


def url_reputation(
    params: UrlReputationParams, soar: SOARClient[UrlReputationSummary], asset: Asset
) -> UrlReputationOutput:
    logger.progress("Querying for url reputation")
    body = {
        "client": {
            "clientId": SAFEBROWSING_CLIENT_ID,
            "clientVersion": SAFEBROWSING_CLIENT_VERSION,
        },
        "threatInfo": {
            "threatTypes": SAFEBROWSING_THREAT_TYPES,
            "platformTypes": SAFEBROWSING_PLATFORM_TYPES,
            "threatEntryTypes": SAFEBROWSING_THREAT_ENTRY_TYPES,
            "threatEntries": [{"url": params.url}],
        },
    }
    resp_json = make_rest_call(
        asset, SAFEBROWSING_THREAT_MATCHES_ENDPOINT, method="POST", body=body
    )

    output = UrlReputationOutput(**resp_json)
    num_matches = len(output.matches or [])
    soar.set_summary(UrlReputationSummary(num_threat_matches=num_matches))
    soar.set_message(
        SAFEBROWSING_THREAT_INFO_RETRIEVED
        if num_matches
        else SAFEBROWSING_NO_THREAT_INFO.format(entity="URL")
    )
    return output
