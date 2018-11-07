# --
# File: safebrowsing_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2016-2018
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Imports local to this App
from safebrowsing_consts import *

import simplejson as json
import requests


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

        action_result = self.add_action_result(ActionResult(dict(param)))

        if (not self._make_rest_call(action_result, endpoint, {}, method=requests.get)):
            return phantom.APP_ERROR

        resp_json = action_result.get_data()[0]

        if (not resp_json.get('threatLists')):
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
            message = "Google Safe Browsing has no threat information about this {}".format(param_type if param_type == 'domain' else param_type.upper())

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
            ret_val = self._reputation(param, 'url')
        if (action_id == self.ACTION_ID_DOMAIN_REPUTATION):
            ret_val = self._reputation(param, 'domain')

        return ret_val


if __name__ == '__main__':

    import sys
    import pudb
    pudb.set_trace()

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = SafeBrowsingConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
