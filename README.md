[comment]: # "Auto-generated SOAR connector documentation"
# Safe Browsing

Publisher: Splunk  
Connector Version: 2.0.5  
Product Vendor: Google  
Product Name: Safe Browsing  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 5.1.0  

This app Integrate with Google Safe Browsing to execute reputation-based actions

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Safe Browsing asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**key** |  required  | password | API Key

### Supported Actions  
[test connectivity](#action-test-connectivity) - Checks API Key with Google Safe Browsing  
[url reputation](#action-url-reputation) - Determine the reputation of a URL  
[domain reputation](#action-domain-reputation) - Determine the reputation of a domain  

## action: 'test connectivity'
Checks API Key with Google Safe Browsing

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'url reputation'
Determine the reputation of a URL

Type: **investigate**  
Read only: **True**

Checks with Google Safe Browsing for records of a URL's previous malicious behavior.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | Determines the URL reputation | string |  `url`  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.url | string |  `url`  `domain`  |   https://www.test.com 
action_result.data.\*.matches.\*.cacheDuration | string |  |  
action_result.data.\*.matches.\*.platformType | string |  |  
action_result.data.\*.matches.\*.threat.url | string |  `url`  `domain`  |   https://www.test.com 
action_result.data.\*.matches.\*.threatEntryType | string |  |  
action_result.data.\*.matches.\*.threatType | string |  |  
action_result.summary.num_threat_matches | numeric |  |  
action_result.message | string |  |   Google Safe Browsing has no threat information about this URL 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'domain reputation'
Determine the reputation of a domain

Type: **investigate**  
Read only: **True**

Checks with Google Safe Browsing for records of a domain's previous malicious behavior.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Determines the domain reputation | string |  `domain`  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.domain | string |  `domain`  `url`  |   www.test.com 
action_result.data.\*.matches.\*.cacheDuration | string |  |  
action_result.data.\*.matches.\*.platformType | string |  |  
action_result.data.\*.matches.\*.threat.url | string |  `domain`  `url`  |   www.test.com 
action_result.data.\*.matches.\*.threatEntryType | string |  |  
action_result.data.\*.matches.\*.threatType | string |  |  
action_result.summary.num_threat_matches | numeric |  |  
action_result.message | string |  |   Google Safe Browsing has no threat information about this domain 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 