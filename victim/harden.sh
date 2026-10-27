#!/usr/bin/env bash
# Hardens the victim to a subset of the CIS Ubuntu 24.04 Benchmark v1.0.0.
#
# `make harden` copies this script into the running victim and runs it as root.
# It is safe to run more than once. Each section names the Wazuh SCA check IDs
# it fixes.
#
# The lab's network settings (CIS 3.3) are kernel settings. A container cannot
# change them itself, so compose.harden.yaml sets them when the victim starts.
set -euo pipefail

say() { printf '\n== %s\n' "$*"; }

# --- 1. Security updates ------------------------------------------------------
# Lynis warning PKGS-7392: packages with known vulnerabilities. The Wazuh agent
# is held at the manager's version and is not upgraded.
say "1. Install security updates"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get upgrade -y -qq
apt-get install -y -qq --no-install-recommends libpam-pwquality

# --- 2. Login banners (35547, 35548) --------------------------------------------
# The banner warns that use is monitored, and does not tell an attacker which OS
# and version run here.
say "2. Login banners"
banner="Authorized use only. All activity on this system is logged and monitored."
for f in /etc/issue /etc/issue.net; do
  echo "$banner" > "$f"
  chown root:root "$f"
  chmod 644 "$f"
done

# --- 3. SSH server (35640, 35643, 35644, 35646, 35647, 35652, 35654, 35655, 35657, 35659)
say "3. SSH server"
getent group sshusers >/dev/null || groupadd sshusers
cat > /etc/ssh/sshd_config.d/50-cis.conf <<'EOF'
# CIS Ubuntu 24.04, section 5.1. Written by harden.sh.
# Only members of sshusers may log in. Nobody is a member yet.
AllowGroups sshusers
Banner /etc/issue.net
# Drop idle sessions after 3 missed keep-alives, 15 seconds apart.
ClientAliveInterval 15
ClientAliveCountMax 3
# No port, X11 or agent forwarding: SSH must not become a tunnel into the lab.
DisableForwarding yes
LoginGraceTime 60
MaxAuthTries 4
# Above 10 half-open logins, refuse 30% of new ones; refuse all above 60.
MaxStartups 10:30:60
MaxSessions 10
# Only strong message authentication codes.
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
IgnoreRhosts yes
HostbasedAuthentication no
PermitEmptyPasswords no
PermitUserEnvironment no
EOF
# The CIS check reads PermitRootLogin from the main file only. The setting in
# sshd_config.d already applies; this line makes the main file say so too.
grep -qE '^\s*PermitRootLogin\s+no' /etc/ssh/sshd_config \
  || sed -i '1i PermitRootLogin no' /etc/ssh/sshd_config
chown root:root /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf
chmod 600 /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf
# Test the new configuration before applying it. A broken sshd config locks
# everyone out, so stop here rather than reload a bad one.
sshd -t
kill -HUP "$(cat /run/sshd.pid)"

# --- 4. Passwords and PAM (35671-35678, 35687-35690, 35693, 35770) -----------------
# The victim has no account with a password, so nobody can log in by password
# today. These settings protect any account added later.
say "4. Passwords and PAM"
# New passwords: at least 14 characters from all 4 character classes, at least
# 2 characters changed from the old one, no more than 3 repeated or sequential
# characters, no dictionary words, and the same rules for root. The CIS checks
# read the main file, so the settings go there.
pwq=/etc/security/pwquality.conf
sed -i -E '/^\s*(difok|minlen|minclass|maxrepeat|maxsequence|dictcheck|enforce_for_root)\b/d' "$pwq"
cat >> "$pwq" <<'EOF'
difok = 2
minlen = 14
minclass = 4
maxrepeat = 3
maxsequence = 3
dictcheck = 1
enforce_for_root
EOF
# Lock an account for 15 minutes after 5 failed logins, root included.
cat > /etc/security/faillock.conf <<'EOF'
deny = 5
unlock_time = 900
even_deny_root
root_unlock_time = 60
EOF
# pam-auth-update profiles, as the CIS benchmark gives them.
cat > /usr/share/pam-configs/faillock <<'EOF'
Name: Enable pam_faillock to deny access
Default: yes
Priority: 0
Auth-Type: Primary
Auth:
	[default=die] pam_faillock.so authfail
EOF
cat > /usr/share/pam-configs/faillock_notify <<'EOF'
Name: Notify of failed login attempts and reset count upon success
Default: yes
Priority: 1024
Auth-Type: Primary
Auth:
	requisite pam_faillock.so preauth
Account-Type: Primary
Account:
	required pam_faillock.so
EOF
# Remember the last 24 passwords, root included. The CIS text says "requisite".
# Wazuh's CIS policy contradicts itself here: check 35675 wants "required" and
# checks 35687-35689 want "requisite". This follows the benchmark text.
cat > /usr/share/pam-configs/pwhistory <<'EOF'
Name: pwhistory password history checking
Default: yes
Priority: 1024
Password-Type: Primary
Password:
	requisite pam_pwhistory.so remember=24 enforce_for_root try_first_pass use_authtok
EOF
# nullok lets an account with an empty password log in. Remove it.
sed -i 's/\s*nullok//g' /usr/share/pam-configs/unix
pam-auth-update --enable unix faillock faillock_notify pwquality pwhistory
# The password history file must be readable by root only.
for f in /etc/security/opasswd /etc/security/opasswd.old; do
  touch "$f"
  chown root:root "$f"
  chmod 600 "$f"
done

# --- 5. Password ageing (35694) ----------------------------------------------------
# Checks 35695, 35696 and 35698 also inspect accounts that have a password. The
# victim has none, so those three cannot pass; the settings below still apply
# to any account added later.
say "5. Password ageing"
sed -i -E 's/^\s*PASS_MAX_DAYS\s+.*/PASS_MAX_DAYS\t365/; s/^\s*PASS_MIN_DAYS\s+.*/PASS_MIN_DAYS\t1/; s/^\s*PASS_WARN_AGE\s+.*/PASS_WARN_AGE\t7/' /etc/login.defs
# Disable an account 45 days after its password expires.
useradd -D -f 45

# --- 6. Restrict su (35668) ----------------------------------------------------
# Only members of sugroup may use su. The group stays empty.
say "6. Restrict su"
getent group sugroup >/dev/null || groupadd sugroup
grep -qE '^auth\s+required\s+pam_wheel.so.*group=sugroup' /etc/pam.d/su \
  || sed -i '/^#\s*auth\s\+required\s\+pam_wheel.so$/a auth required pam_wheel.so use_uid group=sugroup' /etc/pam.d/su
grep -qE '^auth\s+required\s+pam_wheel.so.*group=sugroup' /etc/pam.d/su \
  || echo 'auth required pam_wheel.so use_uid group=sugroup' >> /etc/pam.d/su

# --- 7. Shell defaults (35703, 35705) -------------------------------------------
say "7. Shell defaults"
# New files are not readable by other users.
sed -i -E 's/^\s*UMASK\s+.*/UMASK\t\t027/' /etc/login.defs
for f in /root/.bash_profile /root/.bashrc; do
  touch "$f"
  grep -qE '^\s*umask\s+0027' "$f" || echo 'umask 0027' >> "$f"
done
# Log out idle shells after 15 minutes.
cat > /etc/profile.d/50-cis-tmout.sh <<'EOF'
TMOUT=900
readonly TMOUT
export TMOUT
EOF
chmod 644 /etc/profile.d/50-cis-tmout.sh

# --- 8. Core dumps ---------------------------------------------------------------
# A core dump of a program that handled a password can contain the password.
say "8. Core dumps"
echo '* hard core 0' > /etc/security/limits.d/50-cis-core.conf

# --- 9. Log files (35719, 35722) --------------------------------------------------
say "9. Log files"
# rsyslog creates new log files readable by root and the adm group only. The
# CIS check wants the setting in rsyslog.conf and in /etc/rsyslog.d, so rsyslog
# is also told to read that folder; otherwise a file there would do nothing.
mkdir -p /etc/rsyslog.d
echo '$FileCreateMode 0640' > /etc/rsyslog.d/50-cis.conf
grep -q '^\$IncludeConfig /etc/rsyslog.d/\*.conf' /etc/rsyslog.conf \
  || sed -i '1i $IncludeConfig /etc/rsyslog.d/*.conf' /etc/rsyslog.conf
grep -q '^\$FileCreateMode' /etc/rsyslog.conf || sed -i '1i $FileCreateMode 0640' /etc/rsyslog.conf
# Tighten the files that already exist the same way.
find /var/log -type f -perm /0137 -exec chmod u-x,g-wx,o-rwx {} +
# A HUP only reopens files. Restart rsyslog so it reads the new setting.
kill "$(cat /run/rsyslogd.pid)"
while [ -e /run/rsyslogd.pid ]; do sleep 0.2; done
rsyslogd

say "Done. Run 'make audit LABEL=after' to measure the result."
