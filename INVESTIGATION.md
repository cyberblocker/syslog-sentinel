# Exercise: login success after repeated failures

All bundled events are synthetic. Documentation IP ranges are used.

## Your task

Start with a fresh database, run one TCP demo, and generate the report.

1. Identify the target host, account, and source IP.
2. List the evidence IDs supporting each finding.
3. Decide what the successful login proves and what it does not prove.
4. Inspect the firewall event. Does its presence establish that all later traffic was blocked?
5. Identify the expected host for which you have no evidence.
6. Write the next three investigation steps before checking the answer below.

## Expected observations

Nine events arrive. web-01 reports six failed logins for admin from 198.51.100.23, then an accepted password login. SSH-001 typically references IDs 3–7, and SSH-002 IDs 3–9 on the fresh TCP run. fw-01 reports a deny event. db-01 never appears.

A successful login after failures is suspicious, but does not prove account compromise. It could be an authorized person correcting a password or a synthetic test. A firewall deny log does not establish that every connection or route was blocked. Missing db-01 logs could reflect inactivity, misconfiguration, downtime, or collection failure.

## Example analyst note

**Disposition:** Needs investigation; no confirmed compromise.

**Evidence:** Six reported authentication failures followed by an accepted login for the same host, user, and source. The expected database source has no received messages.

**Next steps:** Validate login authorization with the account owner; check session activity and privilege changes; validate db-01 forwarding and heartbeat delivery.

**Limitations:** These are synthetic, unauthenticated syslog messages. Received hostnames and message contents can be spoofed. No endpoint artifacts or packet capture corroborate them.

## Your incident template

- Title and UTC review time:
- Affected host/account:
- Evidence IDs and timeline:
- Working hypothesis:
- Alternative explanation:
- Missing evidence:
- Next investigative actions:
- Disposition and reasoning:
