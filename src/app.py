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
from soar_sdk.app import App
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger

from .actions import register_actions
from .asset import Asset
from .helpers import make_rest_call
from .safebrowsing_consts import (
    SAFEBROWSING_ERROR_FROM_SERVER,
    SAFEBROWSING_TEST_CONNECTIVITY_PASSED,
    SAFEBROWSING_TEST_CONNECTIVITY_PROGRESS,
    SAFEBROWSING_THREAT_LISTS_ENDPOINT,
)

logger = getLogger()


def create_safebrowsing_app() -> App:
    app = App(
        name="Safe Browsing",
        app_type="information",
        logo="logo_google.svg",
        logo_dark="logo_google_dark.svg",
        product_vendor="Google",
        product_name="Safe Browsing",
        publisher="Splunk",
        appid="3b507b88-a421-4925-b685-1eb4392c5476",
        min_phantom_version="7.0.0",
        fips_compliant=True,
        encrypt_cache_state=True,
        encrypt_ingest_state=True,
        asset_cls=Asset,
    )

    @app.test_connectivity()
    def test_connectivity(soar: SOARClient, asset: Asset) -> None:
        """Checks API Key with Google Safe Browsing"""
        logger.progress(SAFEBROWSING_TEST_CONNECTIVITY_PROGRESS)
        resp_json = make_rest_call(asset, SAFEBROWSING_THREAT_LISTS_ENDPOINT)
        if not resp_json.get("threatLists"):
            logger.debug("Test connectivity failed: no threat lists returned")
            raise ActionFailure(SAFEBROWSING_ERROR_FROM_SERVER)
        logger.progress(SAFEBROWSING_TEST_CONNECTIVITY_PASSED)

    return register_actions(app)


app: App = create_safebrowsing_app()


if __name__ == "__main__":
    app.cli()
