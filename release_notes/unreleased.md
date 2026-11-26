**Unreleased**
* Converted the app to the Splunk SOAR SDK
* Added a make request action for authenticated calls to the Google Safe Browsing API
* The app now requires Splunk SOAR 7.0.0 or later (previously 5.1.0) and Python 3.13 or 3.15
* **Breaking**: failed actions now report "Action failure in <action>: <message>" and no longer store Google's error body or the submitted parameters
* Requests to Google Safe Browsing now time out after 30 seconds
* HTTP redirects from Google Safe Browsing are no longer followed
* Test connectivity now reports "Test connectivity successful" and no longer stores the threat lists data
* Blank URL, domain and endpoint values are now rejected with a clear error