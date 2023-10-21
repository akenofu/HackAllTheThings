## Burp Cert Installation in physical iOS

You can install [**Burp Mobile Assistant**](https://portswigger.net/burp/documentation/desktop/tools/mobile-assistant/installing) **for help installing the Burp Certificate, configure the proxy and perform SSL Pinning.**
Or you can manually follow the next steps:

* Configure **Burp** as the iPhone **proxy in \_Settings**_\*\* --> \*\*_**Wifi**_\*\* --> \*\*_**Click the network**_\*\* --> \*\*_**Proxy**\_
* Access `http://burp` and download the certificate
* Access _**Setting**_ --> _**Profile Downloaded**_ and **Install** it (you will be asked your code)
* Access _**Settings**_ --> _**General**_ --> _**About**_ --> _**Certificate Trust Settings**_ and enable PortSwigger CA
![](/Screenshots/Pasted%20image%2020230804150922.png)

Configure burp to listen on all interface.

![](/Screenshots/Pasted%20image%2020230110102541.png)

> Setting up Burp to proxy your traffic is pretty straightforward. We assume that both your iOS device and host computer are connected to a Wi-Fi network that permits client-to-client traffic. 