# Hardening the lab victim to CIS: what moved the score, and what I skipped

The victim in this lab is an Ubuntu 24.04 container that runs SSH and a Wazuh agent. It is
meant to be attacked, so it starts with default settings. This week I hardened it to part of
the CIS Ubuntu Linux 24.04 Benchmark v1.0.0 and measured the change.

## The result

| Measure | Before | After |
|---|---|---|
| CIS score, from Wazuh's CIS check | 48% | **71%** |
| CIS checks passed | 87 | **134** |
| CIS checks failed | 93 | **54** |
| Lynis hardening index (0-100) | 56 | **65** |
| Lynis warnings | 2 | **1** |

38 failed checks now pass. Installing the password-quality module made 6 more checks apply, and
all 6 pass. The week 1 detection test still passes after hardening, so the lab still sees
attacks.

Every number above comes from [`docs/evidence/hardening/`](evidence/hardening/): one folder
before, one after, and [`fixed.txt`](evidence/hardening/fixed.txt) with the 38 fixed checks.

## How to run it

```bash
make up                    # a fresh lab with the soft victim
make audit LABEL=before    # score it
make harden                # apply the hardening
make audit LABEL=after     # score it again
make test                  # check that detection still works
```

## How the score is measured

Two tools score the victim:

- **Wazuh SCA** runs the CIS Ubuntu 24.04 checks inside the Wazuh agent on the victim. The
  agent sends the result to the Wazuh manager. `make audit` restarts the agent, which makes it
  scan at once, and reads the result from the Wazuh API. The CIS score is the share of checks
  that pass, out of those that apply.
- **Lynis** is a separate audit tool that runs inside the victim. It gives a hardening index
  from 0 to 100, with warnings and suggestions.

Two tools catch different things. Lynis also caught packages with known security fixes not yet
installed, which the CIS checks do not look at.

## What I changed

[`victim/harden.sh`](../victim/harden.sh) makes every change. Each section names the CIS
checks it fixes. The script can run twice with the same result.

1. **Security updates.** Installed pending package updates. This cleared Lynis's
   "vulnerable packages" warning.
2. **Login banners.** `/etc/issue` and `/etc/issue.net` now warn that use is monitored. They no
   longer show the OS name and version, which would help an attacker pick an exploit.
3. **SSH server.**
   - Only members of the group `sshusers` may log in, and the group is empty.
   - Idle sessions close.
   - No port, X11 or agent forwarding, so SSH cannot become a tunnel into the lab.
   - At most 4 password tries per connection, and a 60-second login window.
   - New half-open logins are limited.
   - Only strong message-authentication codes.

   The script tests the new configuration with `sshd -t` before applying it. A broken SSH
   configuration locks everyone out.
4. **Passwords and PAM.** New passwords need 14 characters from all 4 character classes. An
   account locks for 15 minutes after 5 failed logins, root included. The last 24 passwords
   cannot be reused, and empty passwords are refused.
5. **Password ageing.** Passwords expire after 365 days, at least 1 day apart.
6. **`su`.** Only members of the empty group `sugroup` may use `su`.
7. **Shell defaults.** New files are not readable by other users (umask 027). Idle shells log
   out after 15 minutes.
8. **Core dumps.** Turned off, because a crashed program's memory can hold passwords.
9. **Log files.** New and existing log files are readable by root and the `adm` group only.
10. **Network settings** (in [`compose.harden.yaml`](../compose.harden.yaml)). The victim does
    not route packets, ignores ICMP redirects, drops packets with impossible source addresses
    and logs them. A container cannot change these kernel settings itself, so Docker sets them
    when the victim starts.

## What I skipped, and why

54 checks still fail. Each has a reason.

| Checks | Count | Why skipped |
|---|---|---|
| Separate partitions and mount options for `/tmp`, `/var`, `/home` and others | 22 | Disks belong to the Docker host. A container cannot have its own partitions. |
| Firewall: ufw, nftables, iptables | 9 | A firewall inside the container needs the `NET_ADMIN` capability. That would let an attacker who breaks in change the network too. Filtering belongs on the host and on Docker's network. |
| Cron and `at` permissions | 8 | Neither is installed. Installing them to pass a check would add a service and make the victim less safe. |
| AppArmor, bootloader, time sync, auditd, core-dump service, journald upload | 8 | All belong to the host's kernel, boot process or systemd. A container shares the host's kernel and has no boot process or systemd. |
| Minimum password days, expiry warning, inactive lock | 3 | These checks need an account with a password. The victim has none. The settings are in place for any future account. |
| AIDE file integrity tool; sending logs to a remote host | 2 | Already covered another way. The Wazuh agent watches system files for changes and sends the victim's logs, including `/var/log/auth.log`, to the manager. |
| `sudo` installed | 1 | No person administers this machine. Installing `sudo` would pass the check and add an unused program. |
| `pam_pwhistory` module "required" (35675) | 1 | Wazuh's CIS policy contradicts itself. This check wants `required`, and three others want `requisite`. I followed the CIS text, `requisite`. |

Lynis's last warning, "no security repository", is wrong. Ubuntu 24.04 lists its repositories
in `/etc/apt/sources.list.d/ubuntu.sources`, which includes `noble-security`. Lynis 3.0.9 does
not read that file format.

## What I learned

- **A benchmark score is not the goal.** I could have raised the score by installing cron,
  `sudo` and a firewall the victim does not need. Each would add a way in. The table of
  skipped checks is the useful part of the work.
- **Check what the software actually uses, not only the file.** The CIS check said
  `PermitRootLogin` was not disabled. It was already disabled in a drop-in file, which
  `sshd -T` showed. The check reads the main file only. The same thing happened with the
  password-quality settings.
- **Kernel settings affect each other.** Setting `ip_forward` to 0 makes the Linux kernel reset
  `net.ipv4.conf.all.accept_redirects` to 1. Docker applies the victim's settings in no fixed
  order, so this one setting ends up right in some runs and wrong in others. On a normal host,
  files in `/etc/sysctl.d/` apply in a fixed order, so the problem does not arise.
- **Test that hardening does not break the job.** The victim exists to produce SSH logs for
  Wazuh. After hardening, the week 1 brute-force test still raises Wazuh rules 5710 and 5712.
- **Hardening exposed two lab bugs.** Rebuilding the victim on a running lab failed with
  "Duplicate agent name", and the Wazuh API sometimes did not start. Both are fixed: the
  manager now lets a rebuilt agent take over its old name, and the manager's health check
  restarts the API if it is down.

## Limits

- The hardened victim lasts until the next `make up` or `make down`. `make up` brings back the
  soft victim on purpose, because the lab's job is to be attacked.
- One check, 35612 (ICMP redirects), passes in some runs and fails in others, because of the
  kernel setting order above. It passed in the run recorded here.
- The host itself, the Colima VM on this Mac, is not hardened. That would be its own project.
