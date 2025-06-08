---
title: 'Finding SOQL Injection 0-Day in Salesforce'
description: "How an un-exploitable SOQL injection turned into a 0-day in Salesforce itself affecting millions of user records"
date: 2025-06-08T12:12:44+01:00
draft: false
cover:
  image: "salesforce.png"
  alt: "Salesforce"
  relative: true
---

{{< figure src="salesforce.png" width=250px class="side-image" >}}

**TLDR;** While fuzzing all Aura methods present on a specific target, I discovered that the built-in `aura://CsvDataImportResourceFamilyController/ACTION$getCsvAutoMap`, a default aura controller present in all Salesforce deployments, was vulnerable to an SOQL injection. After bypassing SOQL limitations I was able to extract sensitive user information an uploaded documents details, affecting thousands of deployments. 

## A Pleasant Surprise

Earlier this year, I was testing an application built on top of Salesforce and quite quickly realized that in addition to manual testing, I needed some way to fuzz the hundreds (if not thousands) of Aura controllers present in both the application and default to Salesforce. Aura controllers are simply a way that Salesforce define different endpoints across the application, they are conveniently defined in the `app.js` file found in all Salesforce instances. Here the different descriptors define the controller and action, as well as the arguments required to call a specific endpoint. This clear-cut definition made it quite easy to create a parser and fuzzer that could test all these endpoints providing various mutations of the input parameters.

One of the results from this fuzzer was particularly interesting, the response contained the following error:

```json
{
    "exceptionEvent": true,
    "useDefault": false,
    "event": {
        "descriptor": "markup://aura:serverActionError",
        "attributes": {
            "values": {
                "error": {
                    "message": "industries.impl.dataUtils.IndustriesDirectSoapUtil$DirectSoapException: 
                    MALFORMED_QUERY: \nContentVersion WHERE ContentDocumentId = '''\n                                          ^\nERROR at Row:1:Column:239\nunexpected token: '''",
                    "stackTrace": "",
                    "data": {
                        "message": "industries.impl.dataUtils.IndustriesDirectSoapUtil$DirectSoapException: 
                        MALFORMED_QUERY: \nContentVersion WHERE ContentDocumentId = '''\n                                          ^\nERROR at Row:1:Column:239\nunexpected token: '''",
                        "statusCode": 400,
                        "errorCode": "INTERNAL_ERROR"
                    },
                    "id": "-380442143"
                }
            }
        }
    }
}
```

Quickly I realized that the `contentDocumentId` parameter provided by the user to `aura://CsvDataImportResourceFamilyController/ACTION$getCsvAutoMap` was being unsafely embedded in an SOQL query, making it possible to perform an injection and potentially exfiltrate sensitive data out of the database. 

## Bypassing SOQL Restrictions 

Due to the restrictions on SOQL, exploiting injections can be quite tricky. The main hurdles I found in comparison to regular SQL injections are the following:
- You cannot do classic `UNION` injections
- Joins can only happen on entity identifiers
- Often you cannot simply fetch data from other tables because the controller will expect a specific object to be returned
- You are limited to one subquery
- Multi-query is not a thing

These are quite some limitations, however it is important to not give up and find other ways to find impact. 

Let's go back to the vulnerable controller `CsvDataImportResourceFamilyController`, the action `getCsvAutoMap` accepts a `contentDocumentId` as parameter which are default identifiers for uploaded documents on Salesforce and start with the prefix `069` (noice). An example of such an id would be `069TP00000HbJbNYAV`. When the `contentDocumentId` of an existing document was sent, the controller would respond with the following message:

```json
"message": "Cannot invoke \"common.udd.EntityInfo.getEntityId()\" because \"ei\" is null",
```

However, if a document did not exist, the message would be:

```json
"message": "Error in retrieving content document"
```

Now this was the ticket to victory, it is possible to use this response discrepancy to extract sensitive document and user information out of the database even with the restrictions explained above. By setting the `contentDocumentId` parameter as:

```sql
069TP00000HbJbNYAV' AND OwnerId IN (SELECT Id FROM User WHERE Email LIKE 'a%25') AND ContentDocumentId != '
```

it is possible using a script to enumerate the content of columns on any object that has a relation to the `ContentDocument` object. This is because if the sub-query was successful, then a valid `ContentDocument` would be returned and giving us the first response, whereas if it was unsuccessful the server would return the second response. This works exactly like a classical Error-Based Blind SQLi, where the response discrepancy from the server is used to infer the content of the database.

Additionally it is possible to extract details about `ContentDocument` itself using something like: `name LIKE 'a%25'` which would bruteforce the name of the document itself. Depending on the setup, an application could store user password hashes in the database too (Salesforce provides ways to manage users differently, not requiring such a set up at times), making it possible to use this SOQL injection to extract user credentials.

## Generating ContentDocument IDs

Now, we already found an impact, however if you were paying attention you probably noticed that a valid `contentDocumentId` is still required. Meaning that if we get our hands on a valid identifier, we can extract data about that document and the user that uploaded it. This is already quite bad, for example in the context of a forum, any user that attached a picture or a document to a post could be targeted and their sensitive information such as email, full name, address and phone number could be extracted.

While that's all fine and dandy, it requires a user to actively post something in a public setting where such `contentDocumentId` is "disclosed". 

This is when I came across an amazing script: [https://github.com/hypn/misc-scripts/blob/master/salesforce-id-generator.py](https://github.com/hypn/misc-scripts/blob/master/salesforce-id-generator.py), which does exactly what it says, given a single id it can generate X amount of previous or next identifiers. This is because Salsforce IDs do not actually provide a security boundary and are actually somewhat predictable. I incorporated this in my script that bruteforced user details using the SOQL injection, allowing me to disclose document and user data correlated to `ContentDocument` objects that were not public. Essentially, provided a single public document id the script did the following:

1. Generate the previous and next 10,000 `contentDocumentId`s
2. Validate which correspond to existing documents
3. Extracted document names, descriptions and user details using the SOQL injection

With enough time, the script was able to dump all document and user details on the application I was testing. **WIN!**

You can find the script I created here: [https://github.com/Splinter0/mastersplinter/blob/main/content/research/salesforce-sqli/soql-brute.py](https://github.com/Splinter0/mastersplinter/blob/main/content/research/salesforce-sqli/soql-brute.py)

Below are some screenshots of data (sorry, they are heavily redacted for obvious reasons) I was able to extract using this bug:

{{< figure src="card-statements.png" width=400px >}}
{{< figure src="emails.png" width=400px >}}
{{< figure src="leaked.png" width=400px >}}


## Salesforce 0-Day 

After proudly reporting this bug, I received a surprising response:

> Nice finding! However, we did not write this controller...

After reading this, I immediately reported this to Salesforce, who after a bit of back and forth realized that this was actually one of their own default controllers. 

That was the last I heard of them, I reported this in late February/ early April and just a few days ago I noticed the controller was not vulnerable anymore, which is what prompted me to write this post. 

When I reported it I asked them very nicely if I could be added to their bug bounty program, to which they said something along the lines of "we are not looking for new applicants at the moment". Damn! I wasn't looking for a job! Just wanted to report some bugs on your program!

No advisory was issued, no CVE and I could not find any information about this in any of their release notes. Seems like it was quietly patched, which perhaps is a common practice for Salesforce.

## Takeaways

Regardless of this bug being a vulnerability in one of Salesforce's built-in controllers, the technique I presented can be quite valuable to find impact in an otherwise un-exploitable SOQL injection. If you found a place in a Salesforce based app where SOQL injection is possible, but cannot find a way to directly extract information from the database, try thinking of the following:

- Are there any discrepancies in the responses based on your input?
- What other objects and you leverage using a subquery? (aka what tables can you reach)
- Are there multiple injected parameters that can offer better injection points?

Always look for ways to infer data using string and boolean operations, response timing and content can be very effective ways to leverage a blind SOQL injection. And don't forget that you can always generate identifiers for Salesforce objects, use that to your advantage to be able to disclose data on objects you should not be able to see!

## Resources

- [https://www.enumerated.ie/index/salesforce](https://www.enumerated.ie/index/salesforce)
- [https://www.enumerated.ie/index/salesforce-lightning-tinting-the-windows](https://www.enumerated.ie/index/salesforce-lightning-tinting-the-windows)
- [https://github.com/hypn/misc-scripts/blob/master/salesforce-id-generator.py](https://github.com/hypn/misc-scripts/blob/master/salesforce-id-generator.py)


**HACK THE PLANET!**