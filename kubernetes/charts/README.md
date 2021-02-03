# Charts Repo of Athenz servers

## How it works

```bash
cd "$(git rev-parse --show-toplevel)/kubernetes/charts"
helm package athenz-zms
helm package athenz-zts
helm repo index . --url https://raw.githubusercontent.com/AthenZ/athenz/master/kubernetes/charts
git add -A; git commit -S -m "upload helm charts";
git push origin pr-branch
```

## Verify

```bash
helm repo add athenz https://raw.githubusercontent.com/AthenZ/athenz/master/kubernetes/charts
helm search repo athenz/
```
