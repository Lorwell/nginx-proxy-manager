---
outline: deep
---

## Certbot DNS plugins in Nginx Proxy Manager

Nginx Proxy Manager uses Certbot to issue and renew Let’s Encrypt certificates.

When you request a certificate using a DNS challenge, Nginx Proxy Manager installs
the corresponding Certbot DNS plugin for the provider you selected. The available
providers and package versions are defined in
⁠[certbot-dns-plugins.json](https://github.com/Lorwell/nginx-proxy-manager/blob/dev/backend/certbot/dns-plugins.json).

## Renewal activation

nginx reads `ssl_certificate` when it loads its configuration and keeps the parsed certificate in
memory. Writing a renewed certificate to disk is therefore not enough: until nginx is reloaded, the
running workers keep presenting the previous certificate even though the panel and the database
already show the new expiry date.

This fork treats activation as part of renewal:

1. Certbot renews the certificate material and the new expiry is stored.
2. nginx is reloaded; a failed reload is retried a few times.
3. A local TLS handshake using the host's SNI compares the SHA-256 fingerprint nginx presents with
   `fullchain.pem` in `/etc/letsencrypt/live/npm-<id>/`.

If nginx cannot be made to serve the renewed certificate, the renewal request fails with
`error_code: CERTIFICATE_NOT_ACTIVATED` instead of reporting a success that the edge does not
honour. The certificate is not re-issued in that case: the material is valid, and the new expiry is
already stored, so the hourly renewal timer will not pick it up again.

A background check repeats the comparison every ten minutes. When nginx serves a certificate that
differs from the one on disk — for example after a renewal performed outside the API — Nginx Proxy
Manager reloads nginx once and checks again. Reloads triggered by this check are limited to one per
certificate every thirty minutes.

The result is stored on the certificate (`meta.activation`) and shown in the **Activation** column of
the certificate list:

| Status | Meaning |
| --- | --- |
| `verified` | nginx serves the expected material and the stored expiry agrees. |
| `stale` | nginx serves the expected material, but the stored expiry described another certificate. The stored expiry is refreshed from the served certificate. |
| `mismatch` | nginx answered with a different certificate. This is the failure mode that used to be silent. |
| `unverified` | nginx could not be probed (not listening, timeout, client-certificate requirement, ...). |
| `skipped` | nothing is bound to the certificate, so there is no server block to ask. |

Because a `stale` result refreshes `expires_on` from the certificate nginx actually serves, a manual
certificate replacement that bypassed the API no longer leaves the panel behind: the next check
updates the stored expiry and records `verified`. The list still shows the stored expiry; the
activation column is what tells you whether nginx confirms it. Custom certificates are checked
through the same path and reload immediately after upload; `—` means no check result has been
recorded yet.

| Variable | Default | Purpose |
| --- | --- | --- |
| `CERTIFICATE_SERVING_CHECK` | `true` | Set to `false` to disable the periodic serving check. |
| `CERTIFICATE_SERVING_CHECK_INTERVAL_MS` | `600000` | Interval of the periodic serving check. |
| `CERTIFICATE_PROBE_HOST` | `127.0.0.1` | Address used for the TLS fingerprint probe. |
| `CERTIFICATE_PROBE_PORT` | `443` | Loopback port used for the TLS fingerprint probe. |
| `CERTIFICATE_PROBE_TIMEOUT_MS` | `4000` | Timeout of a single TLS probe. |

Certificates bound only to a wildcard host (`*.example.com`) are probed through a freshly generated
name underneath that wildcard, for example `npm-probe-1a2b3c4d.example.com`. The check only performs
a TLS handshake against nginx on loopback, so the generated name does not need to resolve and no
HTTP request is sent; it proves which certificate the wildcard server block loaded, not that a real
customer hostname resolves to it. Certificates that are only used by TCP/UDP stream hosts remain
outside the local check, because their TLS listener is not addressed by a hostname. Verify from
outside the container as well, because only the certificate that is actually served matters to
clients:

```sh
openssl s_client -connect portal.example.com:443 -servername portal.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -enddate -fingerprint -sha256
```

## Important limitations

DNS plugins are maintained independently from Certbot and from Nginx Proxy Manager. As a result:
- Some plugins may lag behind current Certbot or dependency versions.
- A plugin may install package versions that conflict with other Certbot components.
- Support quality varies between providers, and not every plugin is regularly tested in Nginx Proxy Manager.

::: warning
Using more than one DNS provider in the same Nginx Proxy Manager instance may introduce Python
dependency conflicts between Certbot plugins.
:::

## If a DNS plugin does not work

1. Check the Nginx Proxy Manager container logs for Certbot or Python package installation errors.
2. Identify the plugin package and version defined for your provider in
⁠[certbot-dns-plugins.json](https://github.com/Lorwell/nginx-proxy-manager/blob/dev/backend/certbot/dns-plugins.json).
3. Check [PyPI](https://pypi.org/) or the plugin project for a newer compatible release.
4. If needed, update the plugin definition, including any required dependency pins.
5. Submitting a pull request and CI will build a testable docker image for you.

## File reference

Use this file when reviewing or updating provider definitions:
- ⁠[certbot-dns-plugins.json](https://github.com/Lorwell/nginx-proxy-manager/blob/dev/backend/certbot/dns-plugins.json)
