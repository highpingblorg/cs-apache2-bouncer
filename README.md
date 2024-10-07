# mod\_crowdsec
Module for the [Apache HTTP Web Server](https://httpd.apache.org) that allows filtering of unwanted web traffic.

Use with the [Crowdsec API](https://www.crowdsec.net) service to filter unwanted traffic from a website or application fronted by Apache httpd.

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

<Location />
  Crowdsec on
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

