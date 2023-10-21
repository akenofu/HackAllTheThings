- Built on top of [wireguard-go](https://git.zx2c4.com/wireguard-go/about/). Lightweight UDP Tunnels
## Hub and Spoke networks
![](/Screenshots/Pasted%20image%2020221121032232.png)
### Proplems
1. Remote users distant from the VPN concentrator -> High Latency
2. VPN conector distant from data center -> High Latency
3. Single point of failure
![](/Screenshots/Pasted%20image%2020221121032506.png)
![](/Screenshots/Pasted%20image%2020221121032510.png)
## Mesh networks
 Connect all the nodes to all the other nodes? That’s called a mesh network
 ![](/Screenshots/Pasted%20image%2020221121032603.png)
### Proplems
1. Key management: Each node needs to have the keys of all other nodes
2. Nodes would all have to find each other somehow
3. Clients can be inside NATS. hence, dynamic IP Address
4. Clients might be behind firewalls. Hence, no traffic allowed outbound

### Tackling Key managment and Node identification
A “coordination server” is a shared drop box for public keys.
![](/Screenshots/Pasted%20image%2020221121032807.png)
<br>
**Is not this a hub-and-spoke configuration?**
<br>
The so-called “control plane” is hub and spoke, but that doesn’t matter because it carries virtually no traffic. It just exchanges a few tiny encryption keys and sets policies. The data plane is a mesh.

#### Key exchange
1. Nodes generates a random public/private keypair for itself, and associates the public key with its identity.
2. Nodes contact the coordination server and leave their public key and a note about where that node can currently be found
3. The node downloads a list of public keys and addresses in its domain
4. Node configures its WireGuard instance with the appropriate set of public keys.

**A word on security**
The Private key never, ever leaves its node. This is important because the private key is the only thing that could potentially be used to impersonate that node when negotiating a WireGuard session. As a result, only that node can encrypt packets addressed from itself, or decrypt packets addressed to itself.

#### Validating Node integrity
How does the coordination server know which public keys should be sent to which nodes?

Many ways to make the authentication decision:
1. username+password system, also known as PSK (pre-shared keys). Has support for 2FA.
2. System administrator could also set up your machine with a “[machine certificate](https://tailscale.com/kb/1010/machine-certs)” — a key that belongs permanently (or semi-permanently) to the device rather than to the user account. It could use this to ensure that, even with the right username and password, an untrusted device can never publish new keys to the coordination server.
3. Outsourcing authentication to OAuth2, OIDC (OpenID Connect), or SAML provider.
![](/Screenshots/Pasted%20image%2020221121033707.png)

### Tackling NATs and Firewalls
![](/Screenshots/Pasted%20image%2020221121033946.png)
Tailscale uses several very advanced techniques, based on the Internet [STUN](https://tools.ietf.org/html/rfc5389) and [ICE](https://tools.ietf.org/html/rfc8445) standards. Use UDP and QUIC for tcp streams.

### NAT Traversal
#### Firewalls
The most common configuration allows all “outbound” connections and blocks all “inbound” connections.

Every connection ends up being bidirectional; it’s all individual packets flying back and forth. How does the firewall know what’s inbound and what’s outbound?

Stateful firewalls remember what packets they’ve seen in the past and can use that knowledge when deciding what to do with new packets that show up.
![](/Screenshots/Pasted%20image%2020221121034243.png)
Client to Client communication
![](/Screenshots/Pasted%20image%2020221121034513.png)
The trick is to carefully read the rule we established for our stateful firewalls. For UDP, the rule is: **packets must flow out before packets can flow back in.**

To traverse these multiple stateful firewalls, we need to share some information to get underway: the peers have to know in advance the `ip:port` their counterpart is using. Uses a [coordination server](https://tailscale.com/blog/how-tailscale-works/#the-control-plane-key-exchange-and-coordination) to keep the `ip:port` information synchronized in a flexible, secure manner. After connection is established, exchange packages.
![](/Screenshots/Pasted%20image%2020221121034720.png)

#### Connectivity Caveats
Stateful firewalls have limited memory, clients periodically communicate to keep connections alive. If no packets are seen for a while (a common value for UDP is 30 seconds), the firewall forgets about the session, and we have to start over. To avoid this, we use a timer and must either send packets regularly to reset the timers, or have some out-of-band way of restarting the connection on demand.

#### Navigating a NATty network
NATs think of NAT (Network Address Translator) devices as stateful firewalls with one more really annoying feature: in addition to all the stateful firewalling stuff, they also alter packets as they go through.

## References
- [How tailscale works - TailScale](https://tailscale.com/blog/how-tailscale-works/)
- [How NAT traversal works - Tailscale](https://tailscale.com/blog/how-nat-traversal-works/)
