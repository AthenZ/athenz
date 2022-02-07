Host Document Format:

The Host Document is expected to contain the following JSON

```
{
        "provider": "value"
	"uuid": “long hex value",
	"domain": "value",
	"service": "comma separated value",
	"profile": "value”,
	"zone": "openstack cluster",
        "ip": ["value"],
}
```


The Json would be could be dropped into a file such as /var/lib/sia/host_document.

Notes on Service:

The service entry is a comma-separated value. The first one is the primary service name that can be used by tools when the service is not provided in the context.
