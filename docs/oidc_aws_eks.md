# Athenz OIDC Authentication Provider Support for AWS EKS

AWS EKS can be configured to use Athenz as OIDC Authentication Provider to authorize
access to configured EKS clusters.

## Athenz Configuration

OIDC Spec requires that each client is uniquely identified within the OIDC Provider
and has a redirect URI configuration property set. In the context of Athenz, the
EKS cluster administrator first must create a unique service (e.g. `athenz.prod.eks`:
service called `eks` in the domain `athenz.prod`)

Once the service is created, it must be registered with its redirect URI.

```
$ zms-cli -d <domain-name> set-service-endpoint <service-name> <redirect-uri>
```

## AWS EKS Cluster Configuration

In the AWS Console, select EKS service, then choose your cluster from the list.
In the cluster view, select the `Configuratiion` tab and then the `Authentication`
tab. Choose the `Associate Identity Provider` button. In the dialog box specify
the following values (leave others blank):

- Identity Provider Name: athenz
- Issuer URL: `<athenz-zts-endpoint-uri> e.g. https://zts.athenz.io:8443/zts/v1`
- Client ID: `<athenz-service-name> e.g. athenz.prod.eks`
- Groups claim: groups
- Username prefix: athenz
- Groups prefix: athenz

## AWS EKS Cluster Role Binding

Next we need to set up and bind a role with subjects authenticated by
the Athenz OIDC Provider. In this example, we'll use the `cluster-admin`
role and allow any user in the `athenz.prod` domain `eks-cluster-admins`
role to assume the capabilities authorized by the `cluster-admin` role.

Create the following yaml called `cluster-group.yaml`.  It binds an ID token
from Athenz provider having the groups claim of `eks-cluster-admins` to be
authorized as cluster admins in EKS.

```yaml
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
    name: oidc-cluster-admin
roleRef:
    apiGroup: rbac.authorization.k8s.io
    kind: ClusterRole
    name: cluster-admin
subjects:
    - kind: Group
      name: athenz:eks-cluster-admins
```

Use `kubectl` to apply it to your cluster.

```
$ kubectl apply -f cluster-group.yaml
clusterrolebinding.rbac.authorization.k8s.io/oidc-cluster-admin created
```

Checkout the Kubernetes Guide for full details on Role/RoleBinding and 
ClusterRole/ClusterRoleBinding authorization support in your cluster.

## Athenz Role Configuration

Make sure your Athenz domain associated with your ClientID identified
service has the role referenced in the above configuration and the users
who should be authorized as cluster administrators are members in that role.

Based on our example above:

```
$ zms-cli -o yaml -d athenz.prod show-role eks-cluster-admins
name: athenz.prod:role.eks-cluster-admins
modified: "2022-01-21T22:17:59.291Z"
rolemembers:
- membername: user.john
  active: true
  approved: true
```

## OIDC ID Token Support

Install the `zts-idtoken` utility to obtain OIDC ID Tokens from AWS
ZTS instance and request an ID token from ZTS. The returned value from the `zts-idtoken`
utility is the id token that we need to submit to AWS EKS. The utility assumes you are
using X.509 key/cert to authenticate to the ZTS Server. The issued ID tokens are valid
for 1 hour only.

```
$ zts-idtoken -zts <athenz-zts-endpoint-uri> -svc-key-file <service-key> -svc-cert-file <service-cert> -client-id athenz.prod.eks -nonce as324sdfa3 -scope "openid roles" -redirect-uri <redirect-uri>
eyJraWQiOiJ6dHMuZWMudXM.....td2VzdC0yLjAiLCJhbGciOi
```

We can now use the id token as the value of the --token argument for `kubectl` to manage
our AWS EKS cluster:

```
$ kubectl --token=eyJraWQiOiJ6dHMuZWMudXM.....td2VzdC0yLjAiLCJhbGciOi get pods -n sia
NAME              READY   STATUS    RESTARTS   AGE
sia-agent-cfl4n   1/1     Running   0          35d
sia-agent-dwbhn   1/1     Running   0          35d
```
