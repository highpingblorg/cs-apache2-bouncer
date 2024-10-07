# mod\_crowdsec
Module that allows filtering against the crowdsec API.

Use with the [Crowdsec API](https://www.crowdsec.net) service to filter unwanted traffic from a website or application fronted by Apache httpd.

## basic configuration

```
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

