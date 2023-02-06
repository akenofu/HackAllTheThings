# Logic Attacks
Note down the assumptions the developers made when designing the application. Can a step be skipped? Did they account for edge cases?
**Before testing for logic attacks, State the assumptions you think the developers made, ; This makes it easier to identify logic flaws** [^1]
## 2FA
- How is 2FA code linked to the user's session and previous credential login? 
- Can you drop the 2FA request? [^10]
- Can you skip the authentication step and bruteforce the 2FA code? [^2]
- Can you navigate to a different page in the application, before completing the 2FA challenge? [^8]
- Can any 2FA code be used to login with any pair of creds (unlikely)
## E-Commerce
- Can you remove an item from cart or buy negative quantities of an item to get  negative balance? Is that negative balance offsetted by the positive balance? Can you mix both to get discounts or buy items for free?
- Can you overflow the cart cost to have a negative cost? [^3]
- Does the developer assume previous steps always occured? Item paid for, etc. [^9]
- Does developer assume coupons are used in order? Does he keep track of all the used coupons or does he ensures the previous is not the currently supplied coupoun? [^11]
## Account Management
- Can you abuse input field length? [^4]
- Does the developer assume trust is established in previous steps? Can you edit after creating an account, note, etc? [^5]
- Does the developer trust user-input is supplied? [^6] [^7]

[^1]: https://portswigger.net/web-security/logic-flaws
[^2]: https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-broken-logic
[^3]: https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-low-level
[^4]: https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-inconsistent-handling-of-exceptional-input
[^5]: https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-inconsistent-security-controls
[^6]: https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-weak-isolation-on-dual-use-endpoint
[^7]: https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-broken-logic
[^8]: https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-simple-bypass
[^9]: https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-insufficient-workflow-validation
[^10]: https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-authentication-bypass-via-flawed-state-machine
[^11]: https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-flawed-enforcement-of-business-rules