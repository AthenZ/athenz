# mariadb deploy memo

```bash
# ZMS DB
helm install zms-db bitnami/mariadb \
  -f ./k8s/helm/mariadb/wz_values.yaml \
  --set-file "initdbScripts.zms_server\.sql=../servers/zms/schema/zms_server.sql" \
  --dry-run > ./k8s/helm/mariadb/out.yaml

# ZTS DB
helm install zts-db bitnami/mariadb \
  -f ./k8s/helm/mariadb/wz_values.yaml \
  --set "db.name=zts_store" \
  --set "db.user=zts_admin" \
  --set-file "initdbScripts.zms_server\.sql=../servers/zts/schema/zts_server.sql" \
  --dry-run > ./k8s/helm/mariadb/out.yaml
# helm --debug install -f mariadb_values.yaml zms-db-mariadb bitnami/mariadb

# helm upgrade -f ./k8s/helm/mariadb/wz_values.yaml zms-db bitnami/mariadb
helm uninstall zms-db
helm uninstall zts-db

kkk logs zms-db-mariadb-master-0

kkk describe pod zms-db-mariadb-master-0

# helm template --namespace www bitnami/mariadb | kubectl create -f -
```

```bash
kubectl run zms-db-mariadb-client --rm --tty -i --restart='Never' --image  docker.io/bitnami/mariadb:10.3.22-debian-10-r60 --namespace default --command -- bash
# root
mysql -h zms-db-mariadb.default.svc.cluster.local -uroot -p'mariadb_root'
# zms_admin
mysql -h zms-db-mariadb.default.svc.cluster.local -uzms_admin -p'athenz'
mysql -h zms-db-mariadb-slave.default.svc.cluster.local -uzms_admin -p'athenz'

# kubectl get secret --namespace default zms-db-mariadb -o jsonpath="{.data.mariadb-root-password}" | base64 --decode; echo
```

## ZMS
```bash
kubectl run zms-db-mariadb-client --rm --tty -i --restart='Never' --image  docker.io/bitnami/mariadb:10.3.23-debian-10-r0 --namespace default --command -- bash
mysql -h zms-db-mariadb.default.svc.cluster.local -uzms_admin -p zms_server -p'athenz_admin'
mysql -h zms-db-mariadb-slave.default.svc.cluster.local -uzms_admin -p zms_server -p'athenz_admin'
```
## ZTS
```bash
kubectl run zts-db-mariadb-client --rm --tty -i --restart='Never' --image  docker.io/bitnami/mariadb:10.3.23-debian-10-r0 --namespace default --command -- bash
mysql -h zts-db-mariadb.default.svc.cluster.local -uzts_admin -p zts_store -p'athenz_admin'
```
### SQL
```sql
-- show all tables
select table_schema as database_name, table_name
from information_schema.tables
where table_type = 'BASE TABLE'
and table_schema not in ('information_schema','mysql', 'performance_schema','sys')
order by database_name, table_name;

-- show users
SELECT user, host FROM mysql.user;

-- show grants
show grants;
```


### NOTE

```bash
NAME: zms-db
LAST DEPLOYED: Wed May 20 08:44:30 2020
NAMESPACE: default
STATUS: deployed
REVISION: 1
NOTES:
Please be patient while the chart is being deployed

Tip:

  Watch the deployment status using the command: kubectl get pods -w --namespace default -l release=zms-db

Services:

  echo Master: zms-db-mariadb.default.svc.cluster.local:3306
  echo Slave:  zms-db-mariadb-slave.default.svc.cluster.local:3306

Administrator credentials:

  Username: root
  Password : $(kubectl get secret --namespace default zms-db-mariadb -o jsonpath="{.data.mariadb-root-password}" | base64 --decode)

To connect to your database:

  1. Run a pod that you can use as a client:

      kubectl run zms-db-mariadb-client --rm --tty -i --restart='Never' --image  docker.io/bitnami/mariadb:10.3.23-debian-10-r0 --namespace default --command -- bash

  2. To connect to master service (read/write):

      mysql -h zms-db-mariadb.default.svc.cluster.local -uzms_admin -p zms_server -p'athenz_admin'

  3. To connect to slave service (read-only):

      mysql -h zms-db-mariadb-slave.default.svc.cluster.local -uzms_admin -p zms_server -p'athenz_admin'

To upgrade this helm chart:

  1. Obtain the password as described on the 'Administrator credentials' section and set the 'rootUser.password' parameter as shown below:

      ROOT_PASSWORD=$(kubectl get secret --namespace default zms-db-mariadb -o jsonpath="{.data.mariadb-root-password}" | base64 --decode)
      helm upgrade zms-db bitnami/mariadb --set rootUser.password=$ROOT_PASSWORD
```
