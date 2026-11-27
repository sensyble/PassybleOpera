# Security policy

Passyble is a password manager made by Sensyble LLC (Sheridan, Wyoming, USA). We are grateful to everyone
who helps keep its users safe, and we take every report seriously.

This repository, [Passyble-Extension](https://github.com/sensyble/Passyble-Extension), holds the browser extension for Chrome, Edge and Brave. Firefox and Safari repackage the same source, so a bug here usually affects them too. The same policy covers every Passyble repository
and service; it is also published at https://passyble.com/vulnerability-disclosure/.

## Supported versions

Passyble is before version 1.0. Security fixes go into the newest release only; there are no
backports to older versions, so please update (the version is in Settings, About).

| Version | Security fixes |
|---|---|
| Newest release (0.1.x) | Yes |
| Older releases | No: update to the newest release |
| `main` and unreleased branches | Fixes land here first |

## Reporting a vulnerability

Please report privately. Don't open a public issue, pull request or discussion, and don't post details
anywhere public until a fix is out.

**GitHub (preferred for anything in this repository):** on https://github.com/sensyble/Passyble-Extension, open the **Security** tab and
choose **Report a vulnerability** (GitHub private vulnerability reporting). Only the maintainers see the
report, and we can work on the fix and the advisory with you there.

**E-mail:** write to [support@passyble.com](mailto:support@passyble.com) with a subject that starts with "Security:". A person at
Sensyble reads every message. We don't have a PGP key yet; for sensitive details, GitHub's private
reporting is the better channel. If you need another channel, e-mail us without the details first and we
will arrange one.

### What to include

* What is affected: the app or service, its version (Settings, About), the platform, the operating system
  and browser versions.
* What an attacker can do, and what they need first (for example a malicious website, a position on the
  network, a malicious browser extension, malware running as the same user, or physical access to an
  unlocked device).
* Steps to reproduce, a proof of concept, and any configuration or logs that help.
* Whether you know of it being public or exploited.
* Whether and how you would like to be credited.

Use a demo vault with a throwaway master password and test accounts. Never send real passwords, other
people's vault files or personal data you came across.

## What happens next

Sensyble is a small company, so these are aims, not guarantees. If we need longer, we tell you why and
agree a new date with you.

| Step | Our aim |
|---|---|
| Acknowledge your report | within 3 business days |
| First assessment (confirmed or not, and how severe) | within 10 business days |
| Updates while we work on it | at least every 14 days |
| Fix released for a critical issue | within 30 days of confirming it |
| Fix released for a high severity issue | within 60 days |
| Fix released for a medium or low severity issue | within 90 days, or with the next regular release |

We judge severity by the impact on Passyble users, with CVSS as a guide.

**Coordinated disclosure.** When fixed versions are out, we publish a GitHub security advisory (with a CVE
when one applies) and credit you if you wish. Please keep the details private until then, or until 90 days
after your report, whichever comes first; if you want to publish sooner, tell us and we will talk about it.
If an issue is being exploited, we may publish earlier, together with what users should do.

**No bug bounty.** We can't pay rewards at the moment. We credit researchers in the advisory and in the
release notes.

## Safe harbour

Sensyble LLC considers security research done in good faith under this policy to be authorized. For such
research we will not bring or support legal action against you, including under anti-hacking or
anti-circumvention laws (such as the US Computer Fraud and Abuse Act or section 1201 of the DMCA), and we
will not report you to law enforcement. If someone else takes legal action against you for research that
followed this policy, we will make it known that we authorized it. We can't speak for third parties such as
Google, Stripe, GitHub or the operator of someone else's Passyble Server: their own rules apply to their
systems.

Good faith means that you:

* test only your own installations, vaults, accounts and devices, and Passyble Servers you run yourself;
* don't access, change or delete data that isn't yours; if you reach someone else's data by accident, stop,
  don't keep or share it, and tell us;
* don't degrade the service for others: no denial of service or load testing, and keep any automated
  scanning of passyble.com and account.passyble.com light (a few requests per second at most);
* don't use phishing, social engineering or physical attacks against Sensyble's staff, users or premises;
* don't ask for payment in exchange for not disclosing;
* give us reasonable time to fix the issue before you disclose it (see above);
* follow the law where you are.

If you are not sure whether something is allowed, ask us first at [support@passyble.com](mailto:support@passyble.com).

## Scope

In scope:

* **The Passyble apps:** Windows, macOS and Linux (the desktop app, its agent and the browser's native
  messaging host), Android, iOS with its AutoFill extension, and the browser extension for Chrome, Edge,
  Brave, Firefox and Safari.
* **The shared core:** the vault format, encryption and key derivation, sync and merge, import and export,
  and its WebAssembly build.
* **Passyble Server**, the self-hosted server software.
* **Services Sensyble runs:** account.passyble.com, the website passyble.com (with its /dl/ download
  links), and the release files and update feed at github.com/sensyble/pass-releases.
* **The repositories:** PassybleCore, Passyble-Windows, Passyble-macOS, PassybleLinux, Passyble-Android,
  Passyble-iOS, Passyble-Extension, Passyble-Firefox, Passyble-Safari, Passyble-Server, PassybleLanding,
  and the private PassybleAccount and PassybleAdmin, all under github.com/sensyble.

Out of scope:

* **Third-party services** Passyble works with: Google Drive and Google sign-in, Firebase, Stripe, Google
  Play and the other app and add-on stores, WebDAV and cloud folder providers, GitHub. Please report to
  them. A flaw in how Passyble uses them is in scope.
* **Passyble Servers run by other people.** A flaw in the server software is in scope; test it on your own
  instance.
* **Sensyble's internal tools** (such as admin.passyble.com, behind access control): don't test them. If
  you find a way past that access control, report it.
* **An already compromised device**: malware with administrator or root rights, a rooted or jailbroken
  phone running attacker code, or an unlocked device left with an attacker. We still read these reports,
  usually as hardening rather than vulnerabilities; a practical way around a protection we claim (for
  example the lock timeout or screen capture protection) is in scope.
* **Weak master passwords.** A vault is only as strong as its master password, and Passyble enforces a
  minimum when one is set or changed. A way to get around that rule is in scope.
* Reports from automated scanners without a demonstrated impact; missing headers or cookie flags without
  a working attack; SPF, DKIM or DMARC settings; clickjacking on pages without sensitive actions; self-XSS;
  version numbers in responses; denial of service by volume.

## More about Passyble's security

How Passyble protects a vault, and what it can't protect against, is described in PassybleCore's
`docs/ARCHITECTURE.md`. Passyble is new and has not had an outside security review yet.

Thank you for helping keep Passyble and its users safe.
