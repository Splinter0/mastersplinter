---
title: 'Hijacking accounts via BankID Session Fixation attack'
description: "A common misconfiguration found in services integrating BankID, allows attackers to take over victim's accounts exploiting a Session Fixation bug"
date: 2024-03-21T12:12:44+01:00
draft: false
cover:
  image: "bankidbug.png"
  alt: "BankID Bug"
  relative: true
---

{{< figure src="bankidbug.png" width=250px class="side-image" >}}

The Swedish BankID is a form of digital identification used by most if not all Swedish residents to authenticate to multiple services such as: internet providers, online banking services, betting websites and especially governmental websites. 

Living in Sweden myself, and with the hacker mentality always buzzing in my brain, I decided that it would be a very interesting field to do some security research in.

In this post I will be presenting a new vulnerability I found present in most Swedish service providers due to an insecure implementation of BankID's authentication protocol. 

I will briefly go over how such a protocol works, what a vulnerable configuration looks like, how to exploit it, how to remediate it and in the end, what these types of attacks mean for the overall implementation of eIDs.

**TLDR;** When a service uses BankID to authenticate their users it is common for them to incorrectly implement some security features of the protocol which leaves them exposed to a Session Fixation [CWE-384](https://cwe.mitre.org/data/definitions/384.html) vulnerability which can be used by an attacker to hijack a victim's session on that service. Depending on the amount of access the attacker has after exploiting this vulnerability, the severity of such security flaw ranges between **High** and **Critical**

## The BankID Authentication Protocol

BankID is a service which is installed on a user's device and is obtained by requesting it from a Swedish bank, given that you have a Swedish *persunnumer*, a personal fiscal code. The application is installed on the user's device and connected to their fiscal code, essentially tying his/her identity to such an application. This is often how electronic identification systems work: a government authorized and trusted third party hands out a piece of software which is tied to a specific individual and then services integrate with the provider of that piece of software to allow their users to authenticate on their platform, a shared trust model which allows services to easily authenticate people.

BankID is no different and it provides documentation for such services, which from now on will be referred to as Relying Party (RP), so that they can easily integrate their authentication flow with BankID. [https://www.bankid.com/en/utvecklare/guider/teknisk-integrationsguide/rp-introduktion](https://www.bankid.com/en/utvecklare/guider/teknisk-integrationsguide/rp-introduktion).

With BankID there are two main flows which are used to authenticate a user:
- Authenticate on the same device
- Authenticate on another device

We will revisit these two soon, however both flows start with the RP sending a request to BankID's API to start an authentication order. In this post request the RP must specify the `endUserIp` parameter, which contains the ip of the user that is trying to log in, this will be important later on in the report. 

The `/auth` API endpoint will respond with somethings like this:

```
HTTP/1.1 200 OK
Content-Type: application/json
{
  "orderRef":"131daac9-16c6-4618-beb0-365768f37288",
  "autoStartToken":"7c40b5c9-fa74-49cf-b98c-bfe651f9a7c6",
  "qrStartToken":"67df3917-fa0d-44e5-b327-edcc928297f8",
  "qrStartSecret":"d28db9a7-4cde-429e-a983-359be676944c"
}
```

- `orderRef` is an identifier which the RP can use against the `/collect` endpoint to check the authentication status and later on fetch the user information it needs from that person
- `autoStartToken` is a token which is used by the RP to create a [deep link](https://www.singular.net/glossary/deep-linking/) which when clicked will open the BankID app and prompt the user to authenticate himself (**This will be really important**)

`qrStartToken` and `qrStartSecret` will be covered below but are not strictly important to the security research carried out.

In addition to the user's ip, an RP is able to specify more parameters for the authentication order, including: text to be displayed on the BankID application and **authentication requirements**.

Among the authentication requirements, the ones this post will be focusing on are called **certificate policies**, these allow the RP to communicate to BankID which of the two flows was chosen by the user.

### Authentication on the same device

When a user chooses to be authenticated using BankID on the same device, the RP uses the `autoStartToken` to create a deep link which looks like: `bankid:///?autostarttoken=7c40b5c9-fa74-49cf-b98c-bfe651f9a7c6&redirect=https://service.com/login`. This deep link is then picked up by the user's OS and handed off to the BankID application. 

While investigating this flow, an **Open Redirect** vulnerability was found as there is no validation of the `redirect` parameter from BankID's side, I will get to why this additional bug makes the session hijacking attack even more powerful later.

{{< figure src="same.png" width=1000px >}}

### Authentication on another device

{{< figure src="qr.png" class="center-image">}}

When a user chooses to be authenticated using BankID on another device, the RP uses `qrStartToken` and `qrStartSecret` to generate a dynamic QR code (by fetching the next frame's data from the aforementioned `/collect` endpoint) which can be scanned by the user using his Mobile BankID application. 

{{< figure src="mobile.png" width=1000px >}}

## Certificate Policies

These **SHOULD** be specified by the RP when initiating an authentication order, they allow BankID to reject an authentication attempt if the flow does not match in order to mitigate phishing. For example if the user were to choose "authentication on the same device", the RP should communicate that to BankID so that if the authentication is attempted on a Mobile BankID and/or using the QR code, the application can reject that.

In addition to these, once the authentication is complete, the RP is able to fetch the `ipAddress` which was used to open the BankID's application from the `/collect` API endpoint. This **SHOULD** then be checked against the user's ip address on the RP in case he had chosen "authentication on the same device".

The certificate policies, along with the `ipAddress` **SHOULD** be used to make sure that the authentication flow cannot be tampered with. 

Nevertheless while these security measures are in place, BankID fails to outline the importance of them and does not implement them correctly even in their provided example implementation! [https://github.com/BankID/SampleCode](https://github.com/BankID/SampleCode)

## The Session Fixation Bug

So what happens when this protocol is not implemented securely? 

When I first saw the `bankid:///` deep link I was browsing my university application forms which can be accessed by logging with BankID. At first I thought: what happens if I send this deep link to someone? So I sent it to a friend of mine who clicked on it, and to my surprise after he had opened BankID, I had in front of me all of his university applications!

That's when I started looking into the BankID's API, implemented my own RP and learned about all the things I just outlined. 

After a few weeks of research I had developed a script which automated the `bankid:///` deep link grabbing for over 30 RPs, the script would start up a web server and create a path for each service, when a user visited the link for a specific service the script would fetch a fresh link and redirect the user to it. This would cause the device of the user to open the BankID app, and upon authentication I would be authenticated instead of them. 

I was able to do this because:
- RPs did not send the certificate policies to BankID, making it possible for me to fetch a deep link and relay it to a Mobile BankID app
- RPs did not compare the ip address requesting the link with the ip address that had completed the authentication
- RPs provided the link even when the "authenticate on another device" option was chosen

Which led to the Session Fixation vulnerability.

## The Attack

{{< figure src="attack.png" width=1000px >}}

Let's imagine a vulnerable service called AmazingSevice AB, they have implemented the BankID flow following the sample code provided and are hosting such implementation at `https://amazingservice.se/login/bankid`.

A threat actor is interested in the user data stored on AmazingSevice AB and has his victim in sights. He would simply have to automate the `bankid:///` link grabbing, host it on his server and then send the link to his malicious server to his victims. After choosing his phishing delivery of liking (SMS, email, etc.) he will embed the link in the message posing as AmazingSevice AB and requesting the victim to log in. 

Such an account takeover involves very little social engineering, because once the victim clicks on the link, he is immediately prompted to open BankID, leaving the "unknown territory" of the attacker's site for a much more familiar interface, BankID. Additionally the authentication request that the victim would see in the BankID application is actually requested by AmazingSevice AB, making it impossible to detect the fraudulent behavior.

Once the victim authenticates, the attacker's session is authenticated to the victim's account, the victim can further be fooled by exploiting the **Open Redirect** vulnerability present in BankID, allowing the attacker to specify the `redirect` parameter as `https://amazingservice.se/login/bankid`. This would lead the victim to be redirected to the legitimate service website, leaving him simply thinking that the authentication was not successful.

## Demo

Here is a small video demo that shows the attack in action. I could not use one of the companies I reported to, for obvious reason, so instead the demo shows BankID's own demo service being vulnerable to this! 

{{< vimeo 938609744 >}}

On the right corner is the view from the victim receiving the link, here is simulated by visiting the attacker's website. Once the victim visit's the link, the attacker's server opens the headless browser and extract the `bankid:///` link which is then relayed to the victim's phone. In the BankID's app you can see "Test av BankID" which is the legitimate origin for the BankID's demo site. Additionally at the start of the video a VPN is turned on to see that no ip address checks are being carried out during the authentication. In the end it is possible to see that on the attacker's laptop he is logged in as the victim (Johan Johansson).

## The Impact

The Session Fixation bug leads to a **1-click Account Takeover** on any application that user Swedish BankID as an authentication provider and has incorrectly (or not at all) implemented certificate policies and `ipAddress` checks. This is quite serious because often times the services which are using BankID to authenticate their users, have access to quite sensitive data and actions. **Over 30** applications were found vulnerable to this attack, as many as possible were contacted and resulted in 11 accepted bug bounty reports across the major platforms.

One of the services I reported this vulnerability was able to get me in touch with Sweden's national CSIRT, due to how widespread and severe the issue is. Talks have just started so if you wanna be updated go follow me on Twitter (X) [@m4st3rspl1nt3r](https://twitter.com/m4st3rspl1nt3r)

### Remediation

If you're looking for an example of how a secure BankID RP API implementation looks like, I have created one which you can use either as a Golang library or customize and deploy as a microservice. You can find that [here](https://github.com/Splinter0/Identity).

## BankID's Response

Most of the affected services, especially the ones with BBPs and VDPs, were quite receptive and swift to respond to my report. However BankID's response was a bit different. In the one email I received after contacting them multiple times through various channels, they explained that they were aware of the issue but that they felt not much could be done about it in order to keep "ease of integration" for RPs. The planned mitigation, which unfortunately still requires changes to be made on the RPs side, was communicated to me (but for some reason isn't found anywhere on their documentation) as:

> An additional requirement the RP will be able to set is Risk. This will set the acceptable risk level for the transaction. If the risk of the transaction is higher than the required limit the transaction will be blocked  "LOW" - only accept low risk orders
"MODERATE" - accept low and moderate risk orders
If this is set. We will among other things perform the IP-check on our side if it is provided by RP. Other risk parameters the will be riskmonitored if provided are referringDomain, userAgent and deviceIdentifier.

Additionally, a plan to fix the Open Redirect vulnerability is also in place.

My **personal opinion** on this is that if you develop and operate such a critical and highly adopted authentication provider, which is often used to protect very sensitive user information, you should properly document your security mechanisms so that RPs can securely integrate it. Optional security features are completely useless, if a developer can save time not implementing certain features/parameters that's what will happen and we cannot blame it on the RP side. BankID should do their best to move as many anti-fraud and security features to their side to keep "ease of integration" but also make sure to properly document any additional security features which the RP is required to implement; note on **required** not optional.

### Private Company is Public Danger

This part of the blog is purely my opinion.

To me this vulnerability is an example that shows the dangers of letting a private company be in full control of a system which is critical to a country's population. The reason I believe this is more serious than just another vuln in a software company is because BankID is something that is used by over **8.5 million** Swedish residents, it's used to log into your bank, insurance provider, electricity provider and other sensitive platforms which have real world consequences.

If someone finds an Account TakeOver in Facebook, you might lose some pictures, if someone finds a vuln in your country's eID provider (often private) the repercussions on someone's life can be unimaginable.

More and more European countries are adopting eIDs, and the EU is planning on rolling out an EU eID of their own in the coming years (you can read more about this [here](https://commission.europa.eu/strategy-and-policy/priorities-2019-2024/europe-fit-digital-age/european-digital-identity_en)).

{{< figure src="EIDmap.svg" width=400px >}}

My hope is that regulators will push for eID providers to be entirely developed and controlled by public institutions, possibly with the requirement of such systems to be open source and regularly audited for security flaws. 

How can we safely accept such critical pieces of software in our society if they are developed by a private company?

## Further Research

While the main topic of this blog-post was the Session Fixation attack on BankID, I have found that many other authentication/identification providers have all been designed with the same flaw. A new vulnerability class which can be found in providers which require the use of another device (often a mobile phone) to complete the authentication flow. 

The research is ongoing, soon I hope to release more of my findings and a **tool** I've been working on that can be used to automate and exploit such vulnerabilities. Stay tuned for my next topic **Session Fixation by design - Cross-Device Authentication nightmares**

Until then, hack the planet!