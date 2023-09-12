Host Document Format:

The Host Document is expected to contain the following JSON

```
{
        "provider": "value",
	"account_id": "value",
	"project_number": "value",
	"uuid": “long hex value",
	"domain": "value",
	"service": "comma separated value",
	"profile": "value”,
	"zone": "openstack cluster",
        "ip": ["value"],
        "launch_time": "RFC 3339",
}
```


The Json would be dropped into a file such as /var/lib/sia/host_document.

Notes:

The service entry is a comma-separated value. The first one is the primary service name that can be used by tools when the service is not provided in the context.

Stop/start an ec2 instance will update the launch_time.
