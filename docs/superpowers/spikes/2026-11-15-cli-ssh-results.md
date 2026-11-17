# CLI + SSH certificates: spike results (plan 2026-11-15-cli-login-ssh, Task 1)

Run 2026-11-17 on the shared builder. Every container had `--rm`, a `cli-spike-` name and the internal network `cli-spike-net` (or `--network none` for sshd). The scripts are scratch files in `/Volumes/workspace/portcullis/.builder/spike-ssh/` (`vault.sh`, `vault2.sh`, `kc.sh` + `kc/kc.go`, `sshd.sh` + `s3-in.sh`, `s3h-in.sh`, `skkeys.go`) and are not committed.

## Pinned versions

| Component | Image / version |
|---|---|
| Vault | `docker.io/hashicorp/vault:2.2.1@sha256:962a92876e168d68eaaa24b0b8b49bbce1cb63024060a67bba95cd158a366fc2` (core's pin), `Vault v2.2.1 (0e7c41b9…)` |
| Keycloak | `ghcr.io/porelli/portcullis-keycloak@sha256:597d9cccac07fa3da1dff33fe38b7517d52df62e645659c0402bbe87bb551463` (`:edge`), Keycloak 26.8.1 |
| debian:13-slim | `debian@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2`, OpenSSH_10.0p2 Debian-7+deb13u4 |
| ubuntu:24.04 | `ubuntu@sha256:73b999393d07f2bf65a40373778a44dc9a6d54ad7718d29247d8ff9413c4d6a8`, OpenSSH_9.6p1 Ubuntu-3ubuntu13.20 |
| ubuntu:20.04 | `ubuntu@sha256:8feb4d8ca5354def3d8fce243717141ce31e2c428701f6682bd2fafe15388214`, OpenSSH_8.2p1 Ubuntu-4ubuntu0.13 |
| rockylinux:9 | `rockylinux@sha256:03303863808e9cd79f0c58c833db3e5f9cde9f2abe16804a267b05dc54af86e4`, **OpenSSH_9.9p1** (Rocky 9 no longer ships 8.7) |
| Go (sk key builder) | go1.27.3, `golang.org/x/crypto` v0.59.0 |

## Results

| Check | Versions | Result | Observed | Branch for later tasks |
|---|---|---|---|---|
| S1 role write naming the four types in `allowed_user_key_lengths` (`ssh-ed25519`, `ecdsa-sha2-nistp256`, `sk-ssh-ed25519@openssh.com`, `sk-ecdsa-sha2-nistp256@openssh.com`) | Vault 2.2.1 | pass | `Success! Data written`; the read-back lists all four keys | **S1 pass** |
| S1 sign ed25519 / P-256 / sk-ed25519 / sk-ecdsa | Vault 2.2.1 | pass (4/4) | `ssh-keygen -L`: `ssh-ed25519-cert-v01`, `ecdsa-sha2-nistp256-cert-v01`, `sk-ssh-ed25519-cert-v01@openssh.com`, `sk-ecdsa-sha2-nistp256-cert-v01@openssh.com`, key id `pc:alice:t:0123456789abcdef` | `cliapi.SKKeysAccepted = true` |
| S1 sk keys built in Go | x/crypto v0.59.0 | pass | wire `{type, key, "ssh:"}` parses with `ssh.ParsePublicKey`; both implement `ssh.CryptoPublicKey` | — |
| S1a RSA-3072 / P-384 refused by the role | Vault 2.2.1 | pass | `400 public_key failed to meet the key requirements: key of type rsa is not allowed` / `… key of type ecdsa is not allowed` | — |
| S1 note | Vault 2.2.1 | info | Vault maps sk keys onto their base type: a role naming only `ed25519` / `ec` also signs the sk keys. The Hub and enroll refuse other types before Vault (fail closed), the role is the second line | role uses the four full names |
| S2 refresh grant with `scope=openid api:a` after a sign-in with `api:a api:b` | KC 26.8.1 | pass | initial `aud = [portcullis-api https://a.example.com https://b.example.com]`; after refresh `aud = [portcullis-api https://a.example.com]`; a second refresh with `api:b` gives `[portcullis-api https://b.example.com]`; an ungranted scope → `400 invalid_scope` | **S2 pass** (part 3 input only, C44). The realm, scopes and client were made over the admin REST API (a realm made that way gets the built-in scopes), the sign-in was a password grant on the spike client |
| S3 spec §8.9 drop-in: `sshd -t` | all four | pass | `rc=0` | — |
| S3 `-T -C user=alice,host=localhost,addr=127.0.0.1` | all four | pass | `authorizedkeysfile none`, `passwordauthentication no`, `kbdinteractiveauthentication no` | — |
| S3 same for `breakglass` | all four | pass | the distribution's values (`authorizedkeysfile .ssh/authorized_keys[ .ssh/authorized_keys2]`, `passwordauthentication yes`) | — |
| S3 leak: the main file's keywords after `Include` (`X11Forwarding`, `Subsystem`, `UsePAM`, `PrintMotd`) | all four | no leak | `sshd -t` rc=0 (a leaked `Subsystem` would fail it), the `-T` values for `breakglass` are the main file's | **S3 no leak** |
| S3h leak into a drop-in that sorts after ours (`60-later.conf`) | all four | no leak | `X11Forwarding no` / `AllowTcpForwarding no` in `60-later.conf` apply to `breakglass` too; `Subsystem` there passes `sshd -t`: `Match` scope ends at the end of each included file | — |
| S3a `Match all` as the last line | all four | pass, no effect | identical `-T` output | not needed (no leak) |
| S3b `KbdInteractiveAuthentication` inside `Match` on 8.2 | 8.2p1 | **parses** | `sshd -t` rc=0; `-T` shows `kbdinteractiveauthentication no` and `challengeresponseauthentication no` | **S3b pass** |
| S3b' `ChallengeResponseAuthentication` inside `Match` | 8.2p1 | **refused** | `Directive 'ChallengeResponseAuthentication' is not allowed within a Match block` rc=255 (accepted on 9.6, 9.9, 10.0) | the writer always emits `KbdInteractiveAuthentication`, never the old keyword |
| S3c full `-T -C user=…,host=…,addr=…` form | 8.2, 9.6, 9.9, 10.0 | pass | accepted everywhere | C14 form everywhere |
| S3c `-T -C user=alice` alone | 8.2, 9.6, 9.9, 10.0 | accepted (did not fail) | full output printed | irrelevant: C14 always sends the full form |
| S3c on 8.7 | — | not run | `rockylinux:9` now ships 9.9p1; 8.7 is no longer the Rocky 9 package. 8.2 (older) and 9.6 / 9.9 (newer) both pass | C14 unchanged |
| S3d `TrustedUserCAKeys /x` in the main file before `Include` | all four | detectable | `-T` shows `trustedusercakeys /x` for both users | the effective check compares and reports the Problem |
| S3e no `Include` line | all four | detectable | `trustedusercakeys none`, `authorizedprincipalsfile none`, `revokedkeys none` | refuse with the lines to add |
| S3f an earlier drop-in (`10-earlier.conf`) sets `TrustedUserCAKeys` | all four | detectable | `trustedusercakeys /y` | same as S3d |
| S4 role write with C15 string values (AppRole token, spec §7.6 policy) | Vault 2.2.1 | pass | `Success!` (also with `default_critical_options={"source-address":…}`; the signed cert carries `source-address`) | — |
| S4 role write with JSON booleans | Vault 2.2.1 | **refused** | `403 permission denied` | **S4 bool refusal: confirms C15** |
| S4 `allow_host_certificates="true"`, `allowed_extensions="permit-pty,permit-X11-forwarding"`, `key_type="otp"`, an unlisted parameter (`allowed_domains`) | Vault 2.2.1 | refused (4/4) | `403 permission denied` | — |
| S4 extension order | Vault 2.2.1 | strict | `permit-port-forwarding,permit-pty` refused (403): the canonical order of C15 is required | C15 order |
| S4 user sign with `critical_options`, with `cert_type=host`, and with `cert_type=user` | Vault 2.2.1 | refused (3/3) | `403 permission denied` (`denied_parameters` with `[]` denies the key whatever its value) | enroll never sends `cert_type` on the user path |
| S4 user sign `extensions` | Vault 2.2.1 | info | must be a JSON map (`{"permit-pty":""}`); a string is `400 … expected a map`; omitted → the role's `default_extensions` (empty → no extensions at all, not even `permit-pty`); one outside the role → `400 extensions [permit-port-forwarding] are not on allowed list` | enroll always sends the map, `permit-pty` included |
| S4 user sign `ttl` over the role's `max_ttl` | Vault 2.2.1 | refused | `400 ttl is larger than maximum allowed 14400` | — |
| S4b host sign without `cert_type` under `denied_parameters = {"cert_type" = []}` | Vault 2.2.1 | refused | `400 cert_type 'user' is not allowed by role` | **S4b refusal** |
| S4b host sign with `cert_type=host` under the spec policy | Vault 2.2.1 | refused | `403 permission denied` — no host certificate can be issued at all | the host path uses `allowed_parameters = {"cert_type" = ["host"], "*" = []}` |
| S4b corrected host policy | Vault 2.2.1 | pass | `cert_type=host` signs (90 days, principals as sent); `cert_type=user` → 403; none → 400. The key id defaults to `vault-approle-<hash>`, so enroll sends `key_id` | — |
| S4c role `max_ttl="86400"`, sign `ttl="86400"` | Vault 2.2.1 | **uncapped** | the certificate is valid 24 h (`2026-11-17T13:33:50` → `2026-11-18T13:34:20`): the mount's 12 h `max-lease-ttl` applies only when the role's `max_ttl` is 0 | **S4c uncapped** |
| S4c corrected policy (`ttl` / `max_ttl` pinned to the twelve values) | Vault 2.2.1 | pass | `max_ttl="86400"` → 403, `ttl="1800"` → 403, `"43200"` / `"28800"` ok | enroll rounds the role TTL up to a whole hour |
| S4d `read` on `sys/mounts/ssh_user/tune` (and `ssh_host`) only | Vault 2.2.1 | pass, no `sudo` | `max_lease_ttl 12h` / `2160h`; `sys/mounts` itself 403 | **S4d no sudo: C16's full form** |
| S4d `read` on `ssh_host/roles/host` | Vault 2.2.1 | pass | `allow_host_certificates true`, `allow_user_certificates false`, `key_type ca`, `ttl`/`max_ttl` 7776000 | — |
| S4e `list` of `ssh_user/roles` under `ssh_user/roles/hg-*` | Vault 2.2.1 | **refused** | `403` on `GET ssh_user/roles?list=true`: the list path is `ssh_user/roles/`, which `hg-*` doesn't match | plan gap: add `path "ssh_user/roles/" { capabilities = ["list"] }` so enroll can find stale `hg-*` roles |
| S4f `read` of `ssh_user/config/ca` without a grant | Vault 2.2.1 | refused | `403` | add `read` on `ssh_user/config/ca` and `ssh_host/config/ca` for `GET /internal/ssh-ca` (public keys only) |
| S4 role read-back shape | Vault 2.2.1 | info | `allowed_users` and `allowed_extensions` are strings, `ttl` / `max_ttl` integers (seconds), `default_critical_options` a map, `allowed_user_key_lengths` a map of lists | enroll normalises the read-back into `RoleSpec` before the Hub compares (C36) |

## Decisions

- **S1 pass:** part 1 accepts `ssh-ed25519`, `ecdsa-sha2-nistp256`, `sk-ssh-ed25519@openssh.com` and `sk-ecdsa-sha2-nistp256@openssh.com` (`cliapi.SKKeysAccepted = true`). RSA, DSA and ECDSA P-384/521 are refused.
- **S2 pass:** recorded for part 3 (C44); part 1 does not use refresh tokens.
- **S3 no leak:** the drop-in is the spec §8.9 text exactly, without `Match all`.
- **S3b pass:** the writer always emits `KbdInteractiveAuthentication no`; `ChallengeResponseAuthentication` is never written (8.2 refuses it inside `Match`).
- **S3c:** every `sshd -T` call uses C14's full form; 8.7 could not be checked (Rocky 9 ships 9.9 now), both sides of it pass.
- **S4 bool refusal:** confirms C15 (every role field a string, canonical extension order).
- **S4b refusal:** the host sign path is `path "ssh_host/sign/host" { capabilities = ["update"]; allowed_parameters = { "cert_type" = ["host"], "*" = [] } }`; enroll sends `cert_type=host` and a `key_id`.
- **S4c uncapped:** the role path pins `ttl` and `max_ttl` to the twelve values `"3600"`…`"43200"` (whole hours); enroll rounds up to an hour.
- **S4d no sudo:** C16's full form: enroll's policy gains `read` on `sys/mounts/ssh_user/tune`, `sys/mounts/ssh_host/tune` and `ssh_host/roles/host`, and `problems` covers the caps, the host role and the CA key types.
- **S4e/S4f (new):** enroll's policy also gains `list` on `ssh_user/roles/` and `read` on `ssh_user/config/ca` and `ssh_host/config/ca`.
- **User sign path:** enroll never sends `cert_type` or `critical_options`, always sends `extensions` as a map with `permit-pty`.
