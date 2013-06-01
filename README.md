# OAuth 1.0a Provider with Redis in Python

I want to build a scalable OAuth 1.0a Provider that is easy to subclass specifically in authenticating users against
various databases. Focuses in leveraging performance by using Redis as the primary OAuth Provider backend, user
authentications can be handled differently using any other databases.

Coded against [RFC5849](http://tools.ietf.org/html/rfc5849) so please excuse any mishaps, everyone is welcomed to fork
and send pull requests.

## Compatibility Against [RFC5849](http://tools.ietf.org/html/rfc5849)

With this README, I have no plans in supporting 3 legged authentications. I am only supporting XAuth at the moment.
Fork and contribute to add support to 3 legged authentications.

OAuth 1.0 Authorization components are all expected from Authorization header. Example below.

```
Authorization: OAuth realm="http://localhost:5000/",
        oauth_consumer_key="dpf43f3p2l4k3l03",
        oauth_signature_method="HMAC-SHA1",
        oauth_timestamp="137131200",
        oauth_nonce="wIjqoS",
        oauth_signature="74KNZJeDHnMBp0EMJ9ZHt%2FXKycU%3D"
```

## Using

Don't! Not yet.