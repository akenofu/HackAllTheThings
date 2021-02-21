#### Overriding Default Implementation/behavior to bypass certificate checks in testing/development phases left in the application
- Overriding TrustManager 
look for keywords `checkClientTrusted`, `checkServerTrusted`, and `getAcceptedIssuers`
- Does the application ignore TLS issues in webViews. 
	Look for keywords `onReceivedSslError`
- Is the app debugable ? does that affect the previous points
- is `HostnameVerifier` properly configured ? is it accepting any hostname ?



