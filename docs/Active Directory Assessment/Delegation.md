# Delegation
## Unconstrainted Delegation
This a feature that a Domain Administrator can set to any **Computer** inside the domain. Then, anytime a **user logins** onto the Computer, a **copy of the TGT** of that user is going to be **sent inside the TGS** provided by the DC **and saved in memory in LSASS**. So, if you have Administrator privileges on the machine, you will be able to **dump the tickets and impersonate the users** on any machine.

## Constrained Delegation
The Windows Server 2012 R2 and Windows Server 2012 implementation of the Kerberos protocol includes extensions specifically for constrained delegation. Service for User to Proxy (S4U2Proxy) allows a service to use its Kerberos service ticket for a user to obtain a service ticket from the Key Distribution Center (KDC) to a back-end service. These extensions allow constrained delegation to be configured on the back-end service's account, which can be in another domain. For more information about these extensions, see [[MS-SFU]: Kerberos Protocol Extensions: Service for User and Constrained Delegation Protocol Specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/3bff5864-8135-400e-bdd9-33b552051d94) in the MSDN Library.

### Overview
![](/Screenshots/Pasted%20image%2020230608122953.png)

The preceding figure depicts the following protocol steps:
1. The user authenticates to the Key Distribution Center (KDC) by sending a `KRB_AS_REQ`
message, the request message in an Authentication Service (AS) exchange, and requests a forwardable TGT.
2. The KDC returns a forwardable TGT in the `KRB_AS_REP` message, the response message in an Authentication Service (AS) exchange.
3. The user requests a forwarded TGT based on the forwardable TGT from step 2. This is done by the `KRB_TGS_REQ` message.
4. The KDC returns a forwarded TGT for the user in the `KRB_TGS_REP` message.
5. The user makes a request for a service ticket to Service 1 using the TGT returned in step 2. This is done by the `KRB_TGS_REQ` message.
6. The ticket-granting service (TGS) returns the service ticket in a `KRB_TGS_REP`.
7. The user makes a request to Service 1 by sending a `KRB_AP_REQ` message, presenting the 
service ticket, the forwarded TGT, and the session key for the forwarded TGT.
> Note: The `KRB_AP_REQ` message is the request message in the Authentication Protocol (AP) exchange.
8. To fulfil the user's request, Service 1 needs Service 2 to perform some action on behalf of the user. Service 1 uses the forwarded TGT of the user and sends that in a `KRB_TGS_REQ` to the KDC, asking for a ticket for Service 2 in the name of the user.
9. The KDC returns a ticket for Service 2 to Service 1 in a KRB_TGS_REP message, along with a session key that Service 1 can use. The ticket identifies the client as the user, not as Service 1.
10. Service 1 makes a request to Service 2 by a KRB_AP_REQ, acting as the user.
11. Service 2 responds.
12. With that response, Service 1 can now respond to the user's request in step 7.
13. The TGT forwarding delegation mechanism as described here does not constrain Service 1's use of the forwarded TGT. Service 1 can ask the KDC for a ticket for any other service in the name of the user.
14. The KDC will return the requested ticket.
15. Service 1 can then continue to impersonate the user with Service N. This can pose a risk if, for example, Service 1 is compromised. Service 1 can continue to masquerade as a legitimate user to other services.
16. Service N will respond to Service 1 as if it was the user's process.

The Server-for-User-to-Self (S4U2self) extension is intended to be used when the user authenticates to the service in some way other than by using Kerberos. For example, a user could authenticate to a web server by some means private to the web server. The web server could then use S4U2self to get a ticket, with authorization data, just as if the user had used Kerberos originally. This simplifies the server's authorization decision by making all decision paths behave as though Kerberos was used. S4U2self primarily uses the KDC to get information about the user for the caller's own benefit. The Service for User to Proxy (S4U2proxy) extension allows the caller to contact some other service, acting on behalf of the user. The detailed overview is given in the following figure.

![](/Screenshots/Pasted%20image%2020230608123618.png)

From: [[MS-SFU]: Kerberos Protocol Extensions: Service for User and Constrained Delegation Protocol | Microsoft Learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/3bff5864-8135-400e-bdd9-33b552051d94)
## Resource-based Constrained Delegation
Resource-based constrained delegation puts control of delegation in the hands of the administrator owning the resource being accessed. It depends on attributes of the resource service rather than the service being trusted to delegate. As a result, resource-based constrained delegation cannot use the Trusted-to-Authenticate-for-Delegation bit that previously controlled protocol transition. The KDC always allows protocol transition when performing resource-based constrained delegation as though the bit were set.

Because the KDC does not limit protocol transition, two new well-known SIDs were introduced to give this control to the resource administrator. These SIDs identify whether protocol transition has occurred, and can be used with standard access control lists to grant or limit access as needed.