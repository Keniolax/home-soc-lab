# The victim: Ubuntu 24.04 with an SSH server and the Wazuh agent.
# rsyslog writes SSH logins to /var/log/auth.log, and the agent ships that
# file to the manager.

FROM ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac

# The agent must not be newer than the manager, so pin it to the same release.
ARG WAZUH_AGENT_VERSION=4.14.7-1
# Fingerprint of "Wazuh.com (Wazuh Signing Key)". The build stops if the key
# downloaded from Wazuh does not match it.
ARG WAZUH_KEY_FINGERPRINT=0DCFCA5547B19D2A6099506096B3EE5F29111145

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl gnupg lynis openssh-client openssh-server rsyslog \
 && rm -rf /var/lib/apt/lists/*

RUN set -eu; \
    curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH -o /tmp/wazuh.asc; \
    fpr="$(gpg --show-keys --with-colons /tmp/wazuh.asc 2>/dev/null | awk -F: '/^fpr/ { print $10; exit }')"; \
    if [ "$fpr" != "$WAZUH_KEY_FINGERPRINT" ]; then \
      echo "Wazuh signing key fingerprint is '$fpr', expected '$WAZUH_KEY_FINGERPRINT'" >&2; exit 1; \
    fi; \
    gpg --dearmor -o /usr/share/keyrings/wazuh.gpg /tmp/wazuh.asc; \
    rm -rf /tmp/wazuh.asc /root/.gnupg; \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
      > /etc/apt/sources.list.d/wazuh.list; \
    apt-get update; \
    WAZUH_MANAGER=wazuh.manager WAZUH_AGENT_NAME=victim \
      apt-get install -y --no-install-recommends "wazuh-agent=${WAZUH_AGENT_VERSION}"; \
    apt-mark hold wazuh-agent; \
    rm -rf /var/lib/apt/lists/*

COPY rsyslog.conf /etc/rsyslog.conf
COPY sshd-lab.conf /etc/ssh/sshd_config.d/10-lab.conf
COPY agent-lab.xml /tmp/agent-lab.xml
RUN cat /tmp/agent-lab.xml >> /var/ossec/etc/ossec.conf && rm /tmp/agent-lab.xml

COPY entrypoint.sh /usr/local/bin/entrypoint
COPY ssh-probe.sh /usr/local/bin/ssh-probe
RUN chmod 0755 /usr/local/bin/entrypoint /usr/local/bin/ssh-probe

ENTRYPOINT ["/usr/local/bin/entrypoint"]
