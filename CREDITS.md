# Credits

`magiclogin` is derived from **keycloak-magic-link** by **Cloudflight GmbH**,
released under the Apache License 2.0.

- Original project: https://github.com/cloudflightio/keycloak-magic-link
- Copyright © 2025 Cloudflight GmbH
- Original author: Ludwig Burtscher
- License: Apache-2.0 (see [`LICENSE`](LICENSE))

The original work provided the core magic-link authenticators for Keycloak
(the "normal" same-device and "continuation" cross-device flows), the
`MagicLinkSession` entity, the continuation REST resource, and the email/login
templates. Thank you to Cloudflight and Ludwig Burtscher for open-sourcing it.

## What this fork adds

Maintained by the cobdfamily / loginwith.secure team on top of the original:

- Upgraded to Keycloak 26.6.x.
- Deferred user creation — the account is created (or resolved) and the email
  marked verified only when the magic link / code is validated.
- Just-in-time user provisioning (opt-in).
- Optional one-time-code (OTP) path with salted-hash storage and attempt limits.
- Optional `login_hint` shortcut that skips the email form.
- Theme-rendered (FreeMarker) emails that don't depend on a `UserModel`.
- Security hardening (magic-key and OTP stored as hashes, constant-time
  comparison, single-use, reflected-input handling).
- Namespace rebranded to `email.loginwith.secure.keycloak.magiclogin`.

Per the Apache-2.0 license, the upstream copyright and license notices are
retained in [`LICENSE`](LICENSE) and the original authorship
is preserved in the source files.
