# Cachaça
[![codecov](https://codecov.io/github/unsafesystems/cachaca/branch/master/graph/badge.svg?token=PNMZFT2LGU)](https://codecov.io/github/unsafesystems/cachaca)

Cachaça (Portuguese pronunciation: [kaˈʃasɐ](https://dictionary.cambridge.org/pronunciation/english/cachaca)) is a 
distilled spirit made from fermented sugarcane juice. Also known as pinga, caninha, and other names, it is the most 
popular spirit among distilled alcoholic beverages in Brazil. Outside Brazil, cachaça is used almost exclusively as an 
ingredient in tropical drinks, with the caipirinha being the most famous cocktail. In Brazil, caipirinha is often paired
with the dish feijoada. (Source: [Wikipedia](https://en.wikipedia.org/wiki/Cacha%C3%A7a)).


## OIDC/Oauth2 (in progress)
With this library, you can easily enable secure authentication for your applications using OAuth2/OIDC.

### Supported Use Cases
The following use cases are supported:
- Authenticate users through an identity provider (IdP) that is OpenID Connect (OIDC) compliant.

### Preparing to Use an OIDC-Compliant IdP
If you are using an OIDC-compliant IdP, follow these steps:
1. Create a new OIDC app in your IdP. The IdP's DNS must be publicly resolvable.
2. Configure a client ID and a client secret.
3. Obtain the following endpoints published by the IdP: authorization, token, and user info. This information can be found in the config.
4. Ensure that the IdP endpoint certificates are issued by a trusted public certificate authority.
5. Ensure that the DNS entries for the endpoints are publicly resolvable, even if they resolve to private IP addresses.
6. Allow one of the following redirect URLs in your IdP app, whichever your users will use:
    - https://DNS/oauth2/idpresponse
    - https://CNAME/oauth2/idpresponse