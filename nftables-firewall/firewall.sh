#!/bin/bash

# Скрипт настройки firewall (nftables)

# Включение пересылки пакетов (для работы NAT)
sysctl -w net.ipv4.ip_forward="1"

# Очищение старых правил
nft flush ruleset

# Создание глобальных таблиц
nft add table ip filter
nft add table ip nat

# Создание цепочки для фильтрации
nft add chain ip filter INPUT { type filter hook input priority 0 \; policy accept \; }
nft add chain ip filter FORWARD { type filter hook forward priority 0 \; policy accept \; }
nft add chain ip filter OUTPUT { type filter hook output priority 0 \; policy accept \; }

# Создание цепочки для NAT (маршрутизация)
nft add chain ip nat prerouting { type nat hook prerouting priority 0 \; }
nft add chain ip nat postrouting { type nat hook postrouting priority 100 \; }

# Правила для входящего трафика (INPUT)

# Разрешениие localhost (loopback)
nft add rule ip filter INPUT iifname "lo" counter accept

# Запрещение ICMP с внешнего интерфейса (enp0s3)
nft add rule ip filter INPUT iifname "enp0s3" ip protocol icmp counter drop

# Разрешение SSH (порт 22) на внешнем интерфейсе (для управления сервером)
nft add rule ip filter INPUT iifname "enp0s3" tcp dport 22 counter accept

# Разрешение доступа из локальной сети (enp0s8) по протоколам:
# SSH (22)
nft add rule ip filter INPUT iifname "enp0s8" ip saddr 192.168.8.0/24 tcp dport 22 counter accept
# HTTP, HTTPS (80, 443)
nft add rule ip filter INPUT iifname "enp0s8" ip saddr 192.168.8.0/24 tcp dport { 80, 443 } counter accept
# DNS (53)
nft add rule ip filter INPUT iifname "enp0s8" ip saddr 192.168.8.0/24 udp dport 53 counter accept
# DHCP (67, 68)
nft add rule ip filter INPUT iifname "enp0s8" ip saddr 192.168.8.0/24 udp dport { 67, 68 } counter accept
# NTP (123)
nft add rule ip filter INPUT iifname "enp0s8" ip saddr 192.168.8.0/24 udp dport 123 counter accept

# Разрешение уже установленных соединений
nft add rule ip filter INPUT ct state established,related counter accept

# Всё остальное - запрет
nft add rule ip filter INPUT counter drop


# Правила для транзитного трафика (FORWARD)

# Разрешение транзита из внешней сети (enp0s3) в локальную (enp0s8)
nft add rule ip filter FORWARD iifname "enp0s3" oifname "enp0s8" counter accept

# Разрешение транзита из локальной сети (enp0s8) во внешнюю (enp0s3)
nft add rule ip filter FORWARD iifname "enp0s8" oifname "enp0s3" counter accept


# Правила для исходщего трафика (OUTPUT)

# Запрещение недействительных соединений
nft add rule ip filter OUTPUT ct state invalid counter drop


# Правила для NAT

# Включение маскарадинга для выхода в интернет через внешний интерфейс
nft add rule ip nat postrouting masquerade
