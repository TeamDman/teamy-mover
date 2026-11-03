# Direct sender prototype

The Linux `transfer send` command loads a local connection configuration with
`--connect-config`. The Windows receiver uses `transfer receive --config-file`.
Synthetic tests do not prove that a particular cloud route works.

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

## Receiver input validation

The Windows command `transfer receive --validate-only --config-file <path>`
checks local inputs without creating a directory or listener. Its JSON object
contains `version` (1), `manifest_file`, `manifest_sha256`, `transaction_id`,
`server_certificate_der`, `server_key_der`, `client_certificate_der`,
`server_sha256`, `client_sha256`, `target`, `work_parent`,
`destination_parent`, and `final_name`. Paths are absolute; certificates and
the unencrypted PKCS#8 private key are DER encoded. The private key must have
a protected ACL restricted to the current user, administrators and SYSTEM.
The client certificate is used as the locally selected client trust root and
must match the configured pin. Never store the private key in the repository.

Validation checks the manifest, TLS configuration and target, but does not
qualify either directory or prove network access. Omit `--validate-only` to
start a single bounded receiver transaction.

The one-shot integration expects `work_parent` to be the selected user's
profile, `destination_parent` to be its `Downloads` child, and `final_name` to
be `storytelling-recovery`. It retains no-delete-sharing profile and Downloads
handles, creates a protected `storytelling-<transaction-id>` work directory in
the profile, and keeps its journal outside Downloads. Publication uses a
same-volume, no-replace rename, then checks the retained directory identity,
exact file set, file identities, lengths, hashes and named streams. The
receiver does not delete sources or alter the existing Downloads ACL.

The Downloads ACL filter allows ordinary Modify grants that do not include
delete-child, write-DACL or write-owner. The held guard blocks ordinary
competing delete/rename opens, but it does not block attribute-only writes,
prove that profile ancestors cannot be moved, or establish protection against
hostile local principals. The operator's non-interference assumption for the
dedicated stage applies during final publication. Verification reflects what
was held and checked at that time; it is not a power-loss durability guarantee
or a promise against changes after handles are released. A timeout or uncertain
I/O requires local inspection before retrying. Unexpected pending opens retain
their worker and resources until process termination and may prevent normal
runtime shutdown. Check and reconcile the local journal and destination before
retrying any uncertain outcome.
