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

from soar_sdk.app import App

from .domain_reputation import DomainReputationSummary, domain_reputation
from .make_request import http_action
from .url_reputation import UrlReputationSummary, url_reputation


def register_actions(app: App) -> App:
    app.make_request()(http_action)
    app.action(
        description="Determine the reputation of a URL",
        verbose="Checks with Google Safe Browsing for records of a URL's previous malicious behavior.",
        action_type="investigate",
        read_only=True,
        render_as="table",
        summary_type=UrlReputationSummary,
    )(url_reputation)
    app.action(
        description="Determine the reputation of a domain",
        verbose="Checks with Google Safe Browsing for records of a domain's previous malicious behavior.",
        action_type="investigate",
        read_only=True,
        render_as="table",
        summary_type=DomainReputationSummary,
    )(domain_reputation)
    return app
