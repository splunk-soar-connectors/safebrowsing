## Make Request

- Sends an authenticated HTTP request to the Google Safe Browsing API (base URL
  https://safebrowsing.googleapis.com/v4). The API key from the asset configuration is added
  automatically in the X-Goog-Api-Key header, so only the endpoint path (for example,
  /threatLists) needs to be provided.
- Turning off the verify_ssl parameter sends the API key over a connection whose certificate is not
  checked. Leave it enabled unless a trusted proxy requires otherwise.
- The action succeeds whenever Google Safe Browsing answers, even with an error status such as 400
  or 403. Check status_code in the result data to see whether the request worked.
