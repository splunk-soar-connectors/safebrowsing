# File: safebrowsing_connector.py
#
# Copyright (c) 2016-2024 Splunk Inc.
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
#
#
# Phantom App imports
import phantom.app as phantom
import requests
import simplejson as json
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

# Imports local to this App
from safebrowsing_consts import *


# Define the App Class
class SafeBrowsingConnector(BaseConnector):

    ACTION_ID_TEST_CONNECTIVITY = "test_connectivity"
    ACTION_ID_DOMAIN_REPUTATION = "domain_reputation"
    ACTION_ID_URL_REPUTATION = "url_reputation"

    def __init__(self):

        # Call the BaseConnectors init first
        super(SafeBrowsingConnector, self).__init__()

        self._base_url = None
        self._api_key = None

    def initialize(self):

        self._api_key = self.get_config()[SAFEBROWSING_API_KEY]

        self._base_url = SAFEBROWSING_BASE_URL

        return phantom.APP_SUCCESS

    def finalize(self):

        return phantom.APP_SUCCESS

    def _make_rest_call(self, action_result, endpoint, body, method=requests.post):

        params = {'key': self._api_key}

        try:
            response = method(self._base_url + endpoint,
                    data=body,
                    params=params,
                    verify=False)

            resp_json = response.json()

        except Exception as e:
            return (action_result.set_status(phantom.APP_ERROR, SAFEBROWSING_ERR_SERVER_CONNECTION, e))

        action_result.add_data(resp_json)

        if (response.status_code != 200):
            return action_result.set_status(phantom.APP_ERROR, resp_json.get('error', {}).get('message', SAFEBROWSING_ERR_FROM_SERVER))

        return phantom.APP_SUCCESS

    def _test_connectivity(self, param):

        endpoint = 'threatLists'

        self.debug_print("param", param)

        action_result = self.add_action_result(ActionResult(dict(param)))

        if (not self._make_rest_call(action_result, endpoint, {}, method=requests.get)):
            return phantom.APP_ERROR

        resp_json = action_result.get_data()[0]

        if (not resp_json.get('threatLists')):
            self.debug_print("Test Connectivity Failed", resp_json)
            return action_result.set_status(phantom.APP_ERROR, SAFEBROWSING_ERR_FROM_SERVER)

        self.save_progress("Test Connectivity Passed")

        return action_result.set_status(phantom.APP_SUCCESS)

    def _reputation(self, param, param_type):

        self.debug_print("param", param)

        # Add an action result to the App Run
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = 'threatMatches:find'

        client = {'clientId': SAFEBROWSING_CLIENT_ID, 'clientVersion': SAFEBROWSING_CLIENT_VERSION}

        url_list = [{'url': param[param_type]}]

        threat_info = {'threatTypes': SAFEBROWSING_THREAT_TYPES,
                       'platformTypes': SAFEBROWSING_PLATFORM_TYPES,
                       'threatEntryTypes': SAFEBROWSING_THREAT_ENTRY_TYPES,
                       'threatEntries': url_list}

        body = {'client': client,
                'threatInfo': threat_info}

        if (not self._make_rest_call(action_result, endpoint, json.dumps(body))):
            return phantom.APP_ERROR

        resp_json = action_result.get_data()[0]

        if (not resp_json):
            message = "Google Safe Browsing has no threat information about this {}".format(
                param_type if param_type == 'domain' else param_type.upper())
            action_result.set_summary({'num_threat_matches': 0})

        else:

            matches = resp_json.get('matches')

            if (matches):
                action_result.set_summary({'num_threat_matches': len(matches)})

            message = "Threat info retrieved successfully"

        return action_result.set_status(phantom.APP_SUCCESS, message)

    def handle_action(self, param):

        ret_val = None

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if (action_id == self.ACTION_ID_TEST_CONNECTIVITY):
            ret_val = self._test_connectivity(param)
        if (action_id == self.ACTION_ID_URL_REPUTATION):
            ret_val = self._handle_url_reputation(param)
        if (action_id == self.ACTION_ID_DOMAIN_REPUTATION):
            ret_val = self._handle_domain_reputation(param)

        return ret_val

    def _handle_url_reputation(self, param):
        # Handle URL reputation action
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        self.save_progress("In querying for url reputation")

        return self._reputation(param, 'url')

    def _handle_domain_reputation(self, param):
        # Handle Domain reputation action
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        self.save_progress("In querying for domain reputation")

        return self._reputation(param, 'domain')


if __name__ == '__main__':

    import sys

    import pudb
    pudb.set_trace()

    if (len(sys.argv) < 2):
        print("No test json specified as input")
        sys.exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = SafeBrowsingConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
