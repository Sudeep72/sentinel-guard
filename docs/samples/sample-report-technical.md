# SentinelGuard Technical Report — prod-web-01

_Generated 2026-08-05T17:53:42.701037+00:00_

## Server Information
- **Hostname:** prod-web-01 (ubuntu 24.04)
- **Server ID:** 155833bb-4d2a-40ca-8b51-78014c6efe08
- **Scan:** c97183ea-4f6b-42fa-8289-811d6d2824f6 (completed)
- **Scan window:** 2026-08-05T17:53:34.518230 → 2026-08-05T17:53:42.518230

## Security Score
**Overall score: 93.1/100**
Checks: 63/66 passed
Baseline version: 1.0.0

### Category Scores
- permission: 100.0/100 (weight 15%)
- ownership: 100.0/100 (weight 2%)
- ssh: 85.0/100 (weight 20%)
- sudo: 100.0/100 (weight 15%)
- cron: 100.0/100 (weight 3%)
- secret: 75.0/100 (weight 15%)
- docker: 100.0/100 (weight 10%)
- firewall: 100.0/100 (weight 15%)
- kernel: 97.0/100 (weight 5%)

## Severity Summary
- Critical: 1
- High: 1
- Medium: 0
- Low: 1
- Info: 0

## Findings (3)
### ssh (1)
#### [HIGH] SSH root login is permitted
- **Check:** SSH-001
- **Description:** PermitRootLogin is set to yes.
- **Why it matters:** Eliminates the audit trail from su/sudo.
- **Attack scenario:** Attacker with leaked root password gets a shell directly.
- **Current value:** yes
- **Expected value:** no
- **Recommendation:** Set PermitRootLogin no.

### secret (1)
#### [CRITICAL] SSH private key file exposed
- **Check:** SECRET-001
- **Description:** Unencrypted key at /root/.ssh/id_rsa.
- **Why it matters:** Anyone with read access can authenticate as root.
- **Attack scenario:** Attacker copies the key and authenticates elsewhere.
- **Current value:** mode=0644
- **Expected value:** mode=0600
- **Recommendation:** chmod 600, rotate the key.

### kernel (1)
#### [LOW] ASLR is not fully enabled
- **Check:** KERNEL-001
- **Description:** kernel.randomize_va_space=1
- **Why it matters:** Reduces exploit mitigation effectiveness.
- **Attack scenario:** Predictable memory layout aids overflow exploits.
- **Current value:** 1
- **Expected value:** 2
- **Recommendation:** sysctl -w kernel.randomize_va_space=2

## Baseline Comparison
Distro baseline: ubuntu

### Deviations from baseline (3)
- **ssh/PermitRootLogin**: current=`yes`, expected=`no`
- **secret/ssh_private_keys**: current=`secret detected`, expected=`no unprotected SSH private keys`
- **kernel/kernel.randomize_va_space**: current=`1`, expected=`2`