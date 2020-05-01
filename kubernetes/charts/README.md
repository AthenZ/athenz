# Charts Repo of Athenz servers

## How it works

```bash
cd "$(git rev-parse --show-toplevel)/kubernetes/charts"
helm package athenz-zms
helm package athenz-zts
helm repo index . --url https://windzcuhk.github.io/athenz/kubernetes/charts
git add -A; git commit -S -m "upload helm charts";
git push origin gh-pages
```
