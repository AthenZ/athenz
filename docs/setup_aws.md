# Setup Amazon ec2 instance
-----------------

* [Requirements](#requirements)
    * [AWS Account](#aws-account)
* [Launch instance](#launch-instance)
* [Start/Stop Athenz](#startstop-athenz)

## Requirements
---------------

### aws account
-----------

aws account is required to create an ec2 instance for athenz.  Please checkout https://aws.amazon.com/free/


## Launch instance
-------------------

Once you are signed into aws console, go to services and click on ec2.

Launch a new instance by clicking on Launch instance.

Then, on "Step 1: Choose an Amazon Machine Image (AMI)", search for "Athenz" in "Community AMIs" and choose the latest.

You can choose any instance type as needed but for this example, you can pick "t2.micro"

Then, click on "Next:Configure Instance Details"

In this section, select "enable" for "Auto-assign Public IP" so that your instance can be accessed publicly.

On "Step 6: Configure Security Group", add "Custom TCP Rule" for port 9443, 4443 and 8443 with source 0.0.0.0/0.

Lastly, click on "Review and Launch".


## Start/Stop Athenz
-----------------------

```shell
$ cd /opt/athenz
$ sudo ./start.sh
```

Athenz UI Server will be listening on port 9443.  ZMS will be listening on port 4443 and ZTS will be on port 8443.

To access Athenz UI, open your browser with url https://{ec2instance-name}:9443/athenz

default login/password is athenz:athenz

To stop Athenz, execute the following commands:

```shell
$ cd /opt/athenz
$ sudo ./stop.sh
```

