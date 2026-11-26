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
from ..helpers import lookup_threat_matches, require_value
from ..safebrowsing_consts import (
    SAFEBROWSING_NO_THREAT_INFO,
    SAFEBROWSING_THREAT_INFO_RETRIEVED,
)

logger = getLogger()


class DomainReputationParams(Params):
    domain: str = Param(
        description="Determines the domain reputation",
        primary=True,
        cef_types=["domain", "url"],
        column_name="Domain",
    )


class DomainThreatOutput(PermissiveActionOutput):
    url: str | None = OutputField(
        cef_types=["domain", "url"], example_values=["www.test.com"]
    )


class DomainThreatMatchOutput(PermissiveActionOutput):
    # Permissive, like the other output models in this file: the legacy app stored
    # Google's response as-is, and Google may add fields (e.g. threatEntryMetadata).
    threatType: str | None = OutputField(column_name="Threat Type")
    platformType: str | None = OutputField(column_name="Platform Type")
    threatEntryType: str | None = OutputField(column_name="Threat Entry Type")
    threat: DomainThreatOutput | None = None
    cacheDuration: str | None = None


class DomainReputationOutput(PermissiveActionOutput):
    matches: list[DomainThreatMatchOutput] | None = None


class DomainReputationSummary(ActionOutput):
    num_threat_matches: int | None = None


def domain_reputation(
    params: DomainReputationParams,
    soar: SOARClient[DomainReputationSummary],
    asset: Asset,
) -> DomainReputationOutput:
    logger.progress("Querying for domain reputation")
    domain = require_value(params.domain, "domain")
    resp_json = lookup_threat_matches(asset, domain)

    output = DomainReputationOutput(**resp_json)
    num_matches = len(output.matches or [])
    soar.set_summary(DomainReputationSummary(num_threat_matches=num_matches))
    soar.set_message(
        SAFEBROWSING_THREAT_INFO_RETRIEVED
        if num_matches
        else SAFEBROWSING_NO_THREAT_INFO.format(entity="domain")
    )
    return output
