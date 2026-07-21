# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import sys
import types
import unittest
from unittest.mock import Mock


phantom_package = types.ModuleType("phantom")
phantom_package.__path__ = []
phantom_app = types.ModuleType("phantom.app")
phantom_app.APP_ERROR = 1
phantom_app.APP_SUCCESS = 0
phantom_action_result = types.ModuleType("phantom.action_result")
phantom_action_result.ActionResult = object
phantom_base_connector = types.ModuleType("phantom.base_connector")
phantom_base_connector.BaseConnector = object
phantom_package.app = phantom_app
sys.modules.setdefault("phantom", phantom_package)
sys.modules.setdefault("phantom.app", phantom_app)
sys.modules.setdefault("phantom.action_result", phantom_action_result)
sys.modules.setdefault("phantom.base_connector", phantom_base_connector)

from safebrowsing_connector import SafeBrowsingConnector


class SafeBrowsingConnectorTest(unittest.TestCase):
    def test_api_key_is_sent_in_header_not_query_string(self):
        connector = object.__new__(SafeBrowsingConnector)
        connector._base_url = "https://safebrowsing.googleapis.com/v4/"
        connector._api_key = "secret-key"  # pragma: allowlist secret
        action_result = Mock()
        response = Mock(status_code=200)
        response.json.return_value = {"matches": []}
        method = Mock(return_value=response)

        status = connector._make_rest_call(
            action_result,
            "threatMatches:find",
            "{}",
            method=method,
        )

        self.assertEqual(status, 0)
        method.assert_called_once_with(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find",
            data="{}",
            headers={"X-Goog-Api-Key": "secret-key"},
            verify=True,
        )
        self.assertNotIn("params", method.call_args.kwargs)
        action_result.add_data.assert_called_once_with({"matches": []})


if __name__ == "__main__":
    unittest.main()
