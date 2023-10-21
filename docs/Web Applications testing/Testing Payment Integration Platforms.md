# Testing Payment Integration Platforms
Based on: 
- [WSTG - Latest | OWASP Foundation](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/10-Test-Payment-Functionality)

### Test cases
- Adding a negative quantity of an item.
- Repeatedly removing items until the quantity is negative.
- Updating the quantity to a negative value.
- Specify a decimal quantity of an item (such as `0.1`), or a negative quantity (such as `-1`). 
> Depending on the backend processing, adding negative quantities of an item may result in a negative value, reducing the overall cost of the basket.
- Test for HTTP parameter pollution 
- Tamper Price Value in the request
- Tamper `iframe` URL to modify the total 
	```html
	<iframe src="https://example.org/payment_iframe?merchant_id=123&basket_total=22.00" />
	```
- Tamper with currency, especially where applications support multiple currencies.
- Time Delayed Requests: 
	If the value of items on the site changes over time (for example on a currency exchange), then it may be possible to buy or sell at an old price by intercepting requests using a local proxy and delaying them. In order for this to be exploitable, the price would need to either be included in the request, or linked to something in the request (such as session or transaction ID).
- Brute-force discount codes
- Apply multiple discounts at once
- Exploiting Transaction Processing Fees
- Break the payment flow:
	- Replay the order success request to purchase the item multiple items
	- Modifying the contents of a basket after completing the checkout process.
- Try test cards

### Encrypted Transaction Details
In order to prevent the transaction being tampered with, some payment gateways will encrypt the details of the request that is made to them. For example, [PayPal](https://developer.paypal.com/api/nvp-soap/paypal-payments-standard/integration-guide/encryptedwebpayments/#link-usingewptoprotectmanuallycreatedpaymentbuttons) does this using public key cryptography.
#### Test cases:
- Alternatively, it’s possible that the application re-uses the same public/private key pair for the payment gateway and its digital certificate. You can obtain the public key from the server with the following command:
	```bash
	echo -e '\0' | openssl s_client -connect example.org:443 2>/dev/null | openssl x509 -pubkey -noout
	```
- Other payment gateways use a secure hash (or a HMAC) of the transaction details to prevent tampering. The exact details of how this is done will vary between providers (for example, [Adyen](https://docs.adyen.com/online-payments/classic-integrations/hosted-payment-pages/hmac-signature-calculation) uses HMAC-SHA256), but it will normally include the details of the transaction and a secret value. For example, a hash may be calculated as:
	```php
	$secure_hash = md5($merchant_id . $transaction_id . $items . $total_value . $secret)
	```
- Remove the secure hash, as some payment gateways allow insecure transactions unless a specific configuration option has been set.
- Recreate the hash and brute-force the secret

