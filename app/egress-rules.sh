#!/bin/sh
set -eu
iptables -N P8_SSRF_EGRESS
iptables -A OUTPUT -j P8_SSRF_EGRESS
iptables -A P8_SSRF_EGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# Docker rewrites port 53 to dynamic resolver ports before the filter chain.
# Permit TCP/UDP only to that one embedded-resolver address, not all loopback.
iptables -A P8_SSRF_EGRESS -d 127.0.0.11 -p udp -j ACCEPT
iptables -A P8_SSRF_EGRESS -d 127.0.0.11 -p tcp -j ACCEPT
iptables -A P8_SSRF_EGRESS -d 93.184.216.53 -p udp --dport 53 -j ACCEPT
iptables -A P8_SSRF_EGRESS -d 93.184.216.53 -p tcp --dport 53 -j ACCEPT
# Narrow exception used by the Docker healthcheck (not a blanket loopback permit).
iptables -A P8_SSRF_EGRESS -d 127.0.0.1 -p tcp --dport 8080 -j ACCEPT
iptables -A P8_SSRF_EGRESS -d 93.184.216.10 -p tcp -m multiport --dports 80,443 -j ACCEPT
iptables -A P8_SSRF_EGRESS -j REJECT --reject-with icmp-admin-prohibited
ip6tables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ip6tables -A OUTPUT -j REJECT
echo '[egress] active: only lab DNS, healthcheck and approved fixture; IPv6 denied'
iptables -S P8_SSRF_EGRESS
ip6tables -S OUTPUT
