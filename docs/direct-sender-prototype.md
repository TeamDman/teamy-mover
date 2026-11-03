# Direct sender prototype

The Linux `transfer send` command can load a local connection configuration
with `--connect-config`. This is a sender only: the Windows receiver and its
publication gate are not operational yet. Do not treat a successful build or
the earlier in-memory tests as proof that a cloud route works.

Combine the option with `--manifest-file`, `--manifest-sha256`,
`--transaction-id`, and `--source-map`, using the same approved manifest and
source-map format as `--verify-only`. The configuration is a JSON object with
these fields:

```json
{
  "version": 1,
  "proxy_authority": "proxy.example:8080",
  "target": "100.64.0.1:49152",
  "server_certificate_der": "/private/server.der",
  "client_certificate_der": "/private/client.der",
  "client_key_der": "/private/client-key.pk8",
  "server_sha256": "<64 lowercase hexadecimal characters>",
  "client_sha256": "<64 lowercase hexadecimal characters>"
}
```

Use the actual locally approved proxy, Tailscale IPv4 target and pins; these
values are examples, not credentials or a live destination. The certificates
must be DER-encoded and the private key must be unencrypted PKCS#8 DER, owned
by the current Linux user, with no group or other access. Keep the key out of
the repository, logs and command arguments. File paths must be absolute and
free of symlinks. The sender uses the configured server certificate as a trust
root, validates TLS identity and both exact leaf pins, and never deletes the
sources. The proxy address is locally supplied and CONNECT is attempted only
to the selected tailnet target. No alternate route is tried.

The sender applies the existing process limit before starting its async
runtime. A commit failure, timeout or disconnect may leave publication
uncertain and requires receiver-side inspection. A reported successful
publication is explicitly durability-unconfirmed.
