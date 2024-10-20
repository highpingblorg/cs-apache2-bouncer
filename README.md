# mod\_crowdsec
Module for the [Apache HTTP Web Server](https://httpd.apache.org) that allows filtering of unwanted web traffic.

Use with the [Crowdsec API](https://www.crowdsec.net) service to filter unwanted traffic from a website or application fronted by Apache httpd.

When blocked, requests will return 429 Too any Requests, as defined in
[RFC6585](https://datatracker.ietf.org/doc/html/rfc6585#section-4). This
response can be further customised into a fixed response or an URL or path to
redirect to by using the
[ErrorDocument](https://httpd.apache.org/docs/2.4/mod/core.html#errordocument)
directive in Apache httpd. Full details for customising the error handling
can be found here: [Custom Error Responses](https://httpd.apache.org/docs/2.4/custom-error.html)

## basic configuration

```
# Load required modules
<IfModule !crowdsec_module>
  LoadModule crowdsec_module modules/mod_crowdsec.so
</IfModule>
<IfModule !proxy_module>
  LoadModule proxy_module modules/mod_proxy.so
</IfModule>
<IfModule !proxy_http_module>
  LoadModule proxy_http_module modules/mod_proxy_http.so
</IfModule>
<IfModule !socache_shmcb_module>
  LoadModule socache_shmcb_module modules/mod_socache_shmcb.so
</IfModule>

# Basic configuration:
CrowdsecURL http://localhost:8080
CrowdsecAPIKey [...]

CrowdsecCache shmcb
CrowdsecCacheTimeout 60

CrowdsecFallback block

<Proxy "http://localhost:8080">
  ProxySet connectiontimeout=1 timeout=5
</Proxy>

<Location />
  Crowdsec on
</Location>

<Location /one/>
  ErrorDocument 429 "IP Address Blocked"
</Location>

<Location /two/>
  ErrorDocument 429 https://somewhere.example.com/blocked.html
</Location>

<Location /three/>
  ErrorDocument 429 /you-are-blocked.html
</Location>
```

## directives

| Directive | Description |
| ------ | ----------- |
| Crowdsec  | Enable crowdsec in the given location. Defaults to 'off'. |
| CrowdsecURL   | Set to the URL of the Crowdsec API. For example: http://localhost:8080. |
| CrowdsecAPIKey | Set to the API key of the Crowdsec API. Add an API key using 'cscli bouncers add'. |
| CrowdsecCache    | Enable the crowdsec cache. Defaults to 'none'. Options detailed here: https://httpd.apache.org/docs/2.4/socache.html. |
| CrowdsecCacheTimeout    | Set the crowdsec cache timeout. Defaults to 60 seconds. |
| CrowdsecFallback  | How to respond if the Crowdsec API is not available. 'fail' returns a 500 Internal Server Error. 'block' returns a 429 Too Many Requests. 'allow' will allow the request through. Default to 'fail'. |

## caching

The results of a ban may be optionally cached using the [Apache shared object cache](https://httpd.apache.org/docs/2.4/socache.html).

The CrowdsecCacheTimeout directive controls the amount of time in seconds that the
response will be cached for.

## fallback

Should the Crowdsec API be unavailable, you can control the behaviour of mod_crowdsec
with the CrowdsecFallback directive. By default, failure to determine the status of
an IP address will cause mod_crowdsec to return 500 Internal Server Error. To override
this and have mmod_crodsec block all requests, set to 'block'. If you wish to fail open,
set this to 'allow'.

The timeouts for connection to and communication with the crowdsec API are controlled by
mod_proxy using the [ProxySet](https://httpd.apache.org/docs/2.4/mod/mod_proxy.html#proxyset) directive. Set the connectiontimeout and timeout options to
control how long to wait for crowdsec to respond.
