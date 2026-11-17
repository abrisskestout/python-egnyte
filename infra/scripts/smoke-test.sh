#!/usr/bin/env bash
# After a deployment: wait until the site answers, then check that it is protected.
#
#   bash infra/scripts/smoke-test.sh https://egnyte-test.azurewebsites.net
#
# 1. GET /healthz must become 200 (it is the one path excluded from sign-in).
# 2. GET / with no sign-in must NOT be served: 302 (redirect to Microsoft sign-in), 401 or 403. A 200 means
#    App Service Authentication is not protecting the site, and the app trusts the identity headers that it
#    adds, so that fails the deployment.
set -euo pipefail

base="${1:?usage: smoke-test.sh https://<host>}"
base="${base%/}"
attempts="${MAX_ATTEMPTS:-30}"
delay="${RETRY_DELAY:-10}"
CURL="${CURL:-curl}"   # overridable so the tests can use a fake

status() { "$CURL" -s -o /dev/null -w '%{http_code}' --max-time 20 "$1" || true; }

for i in $(seq 1 "$attempts"); do
  code="$(status "$base/healthz")"
  if [ "$code" = "200" ]; then
    echo "Site is up: $base/healthz answered 200."
    break
  fi
  echo "Attempt $i of $attempts: $base/healthz answered ${code:-nothing}; waiting ${delay}s."
  if [ "$i" = "$attempts" ]; then
    echo "::error::$base/healthz never answered 200. Look at the app log: az webapp log tail --name <app> --resource-group <group>"
    exit 1
  fi
  sleep "$delay"
done

code="$(status "$base/")"
case "$code" in
  302|401|403) echo "Sign-in is enforced: $base/ answered $code without a session." ;;
  *)
    echo "::error::$base/ answered ${code:-nothing} without a session. Expected 302, 401 or 403: App Service Authentication is NOT protecting the site."
    exit 1
    ;;
esac
