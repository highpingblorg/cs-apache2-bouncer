# Apache2 Crowdsec Bouncer

Module for the [Apache HTTP Web Server](https://httpd.apache.org) that allows filtering of unwanted web traffic.

Use with the [Crowdsec API](https://www.crowdsec.net) service to filter unwanted traffic from a website or application fronted by Apache httpd.

When blocked, requests will return 302 Temporary Redirect to the fully qualified
URL specified in the CrowdsecLocation directive. The URL is interpreted using the
[expression API](https://httpd.apache.org/docs/2.4/expr.html) allowing the
interpretation of variables in the request. If CrowdsecLocation points at a relative
URL, we return an internal redirect to the specified path.

If the CrowdsecLocation directive is not specified, we return 429 Too any Requests,
as defined in
[RFC6585](https://datatracker.ietf.org/doc/html/rfc6585#section-4). This
response can be further customised into a fixed response or an URL or path to
redirect to by using the
[ErrorDocument](https://httpd.apache.org/docs/2.4/mod/core.html#errordocument)
directive in Apache httpd. Full details for customising the error handling
can be found here:
[Custom Error Responses](https://httpd.apache.org/docs/2.4/custom-error.html)

# Build & Installation

> To build debian package:

```bash
dpkg-buildpackage -us -uc
```

> Installation

```bash
sudo dpkg -i crowdsec-apache2-bouncer_1.0.0_amd64.deb
sudo a2enmod mod_crowdsec
```

# Configuration

Configuration file is in `/etc/crowdsec/bouncers/crowdsec-apache2-bouncer.conf` :

```
## Basic configuration
CrowdsecURL http://127.0.0.1:8081
CrowdsecAPIKey this_is_a_bad_password

# Behavior if we can't reach (or timeout) LAPI
# block | allow | fail
CrowdsecFallback block

# Target location for blocked requests. If not set, the default is to return HTTP 429
#CrowdsecLocation /denied


## Cache configuration

# Cache engine used
CrowdsecCache shmcb
# Expiration in seconds
CrowdsecCacheTimeout 60
```

You then need to add `Crowdsec on` to the relevant locations.


<!-- 

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
  CrowdsecLocation "IP Address Blocked"
</Location>

<Location /two/>
  CrowdsecLocation https://somewhere.example.com/blocked.html
</Location>

<Location /three/>
  CrowdsecLocation /you-are-blocked.html
</Location>

<Location /four/>
  CrowdsecLocation https://somewhere.example.com/blocked.html?ip=%{REMOTE_ADDR}
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
| CrowdsecFallback  | How to respond if the Crowdsec API is not available. 'fail' returns a 500 Internal Server Error. 'block' returns a 302 Redirect (or 429 Too Many Requests if CrowdsecLocation is unset). 'allow' will allow the request through. Default to 'fail'. |
| CrowdsecLocation | Set to the URL to redirect to when the IP address is banned. May be a path, or a full URL. For example: /sorry.html |

## caching

The results of a ban may be optionally cached using the [Apache shared object cache](https://httpd.apache.org/docs/2.4/socache.html).

The CrowdsecCacheTimeout directive controls the amount of time in seconds that the
response will be cached for.

## fallback

Should the Crowdsec API be unavailable, you can control the behaviour of mod_crowdsec
with the CrowdsecFallback directive. By default, failure to determine the status of
an IP address will cause mod_crowdsec to return 500 Internal Server Error. To override
this and have mod_crowdsec block all requests, set to 'block'. If you wish to fail open,
set this to 'allow'.

The timeouts for connection to and communication with the crowdsec API are controlled by
mod_proxy using the [ProxySet](https://httpd.apache.org/docs/2.4/mod/mod_proxy.html#proxyset) directive. Set the connectiontimeout and timeout options to
control how long to wait for crowdsec to respond. -->
