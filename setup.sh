#!/bin/bash
# VLESS + Reality на Xray. Идемпотентно: можно гонять повторно.
set -eu

log(){ echo "[$(date +%H:%M:%S)] $*"; }

# Скрипт ставится на чистый сервер. Если порт уже держит другая программа
# (веб-сервер, VPN-панель), Xray молча не запустится — проверяем до любых правок.
# Свой xray от прошлого прогона не мешает. Если владельца порта не видно
# (урезанный root в контейнерных VPS), не гадаем — сбой поймает проверка запуска.
for p in 443 8443; do
  who=$(ss -Htlnp "sport = :$p" 2>/dev/null | grep -oP 'users:\(\("\K[^"]+' | grep -vx xray | head -1 || true)
  if [ -n "$who" ]; then echo "PORT=$p"; echo "BUSY_BY=$who"; echo "ERROR=port"; exit 2; fi
done

log "1/6 установка Xray"
# Без DNS не скачать Xray, а прокси не откроет ни одного сайта. На свежих VPS
# резолвер хостера бывает мёртвым — тогда прописываем публичный.
# Строка ERROR=… — сигнал для index.js, какой совет показать.
resolves(){ timeout 15 getent hosts github.com >/dev/null 2>&1; }
online(){ for ip in 1.1.1.1 8.8.8.8; do timeout 5 bash -c "</dev/tcp/$ip/443" 2>/dev/null && return 0; done; return 1; }
if ! resolves; then
  online || { echo "ERROR=offline"; exit 2; }
  cp -P /etc/resolv.conf /etc/resolv.conf.bak-vless 2>/dev/null || true
  [ -L /etc/resolv.conf ] && rm -f /etc/resolv.conf
  printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > /etc/resolv.conf
  resolves || { echo "ERROR=dns"; exit 2; }
  log "    DNS не работал — прописал 1.1.1.1 и 8.8.8.8"
fi
# Установщик берём с проверенного коммита, а не с main: 18.10.2026 (1142d3d) там
# включили set -euo pipefail, и он стал падать на tput без $TERM (SSH без терминала).
# Сам Xray он всё равно ставит последней версии. TERM — на случай смены коммита.
INSTALLER_URL=https://raw.githubusercontent.com/XTLS/Xray-install/e741a4f56d368afbb9e5be3361b40c4552d3710d/install-release.sh
# Версию Xray тоже фиксируем. С 26.10.21 сервер REALITY отвергает Client Hello
# без X25519MLKEM768 (xtls/reality 8cdf7bf): короткий отпечаток edge не проходит,
# а Clash Verge (mihomo 1.19.33) не подключается даже с chrome. 26.3.27 принимает
# оба — проверено 26.10.2026. Стоит другая версия — ставим поверх эту.
XRAY_VERSION=26.3.27
has_xray(){ xray version 2>/dev/null | grep -q "^Xray $XRAY_VERSION "; }
if ! has_xray; then
  # Установщик ставит unzip через apt без apt update. На свежих образах списки
  # пакетов пустые, и он падает с «Installation of unzip failed». Ставим сами;
  # таймаут блокировки — на случай, если apt уже занят автообновлением.
  if ! type -P unzip >/dev/null && type -P apt-get >/dev/null; then
    { apt-get -o DPkg::Lock::Timeout=180 update \
      && DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=180 -y --no-install-recommends install unzip
    } >/tmp/unzip-install.log 2>&1 || true
  fi
  INSTALLER=$(curl -fsSL --retry 3 "$INSTALLER_URL") \
    || { echo "ERROR=download"; exit 2; }
  TERM=xterm bash -c "$INSTALLER" @ install --version "v$XRAY_VERSION" >/tmp/xray-install.log 2>&1 || true
fi
has_xray || { tail -5 /tmp/xray-install.log 2>/dev/null; echo "ERROR=install"; exit 2; }
xray version 2>/dev/null | head -1 || true

log "2/6 генерация ключей"
UUID=$(xray uuid)
KEYS=$(xray x25519)
PRIV=$(echo "$KEYS" | awk '/PrivateKey/{print $2}')
PUB=$(echo "$KEYS"  | awk -F': ' '/Password|PublicKey/{print $2; exit}')
SID=$(openssl rand -hex 8)

log "3/6 подбор dest — только ECDSA, цепочка обязана влезать в буфер REALITY"
DEST=""
for d in www.speedtest.net www.bing.com dl.google.com www.cloudflare.com one.one.one.one; do
  alg=$(timeout 12 openssl s_client -connect ${d}:443 -servername ${d} -tls1_3 </dev/null 2>/dev/null \
        | openssl x509 -noout -text 2>/dev/null | grep -m1 "Public Key Algorithm" | sed 's/.*: //')
  alpn=$(timeout 12 openssl s_client -connect ${d}:443 -servername ${d} -alpn h2 -tls1_3 </dev/null 2>/dev/null | grep -c "ALPN protocol: h2" || true)
  if [ "$alg" = "id-ecPublicKey" ] && [ "$alpn" = "1" ]; then
    DEST="$d"; log "    выбран: $d (ECDSA + h2)"; break
  else
    log "    пропуск: $d ($alg)"
  fi
done
[ -n "$DEST" ] || { echo "ОШИБКА: не найден подходящий dest"; exit 1; }

log "4/6 конфигурация (порты 443 + 8443)"
python3 - "$UUID" "$PRIV" "$SID" "$DEST" <<'PY'
import json, sys, copy
uuid, priv, sid, dest = sys.argv[1:5]
inb = {
  "tag":"vless-reality","listen":"0.0.0.0","port":443,"protocol":"vless",
  "settings":{"clients":[{"id":uuid,"flow":"xtls-rprx-vision","email":"clash"}],"decryption":"none"},
  "streamSettings":{"network":"tcp","security":"reality","realitySettings":{
      "show":False,"dest":f"{dest}:443","xver":0,"serverNames":[dest],
      "privateKey":priv,"shortIds":[sid]}},
  "sniffing":{"enabled":True,"destOverride":["http","tls","quic"],"routeOnly":True}
}
alt = copy.deepcopy(inb); alt["port"]=8443; alt["tag"]="vless-reality-8443"
cfg = {
  "log":{"loglevel":"warning","access":"/var/log/xray/access.log","error":"/var/log/xray/error.log"},
  "inbounds":[inb, alt],
  "outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"block","protocol":"blackhole"}],
  "routing":{"domainStrategy":"IPIfNonMatch",
             "rules":[{"type":"field","ip":["geoip:private"],"outboundTag":"block"}]}
}
json.dump(cfg, open('/usr/local/etc/xray/config.json','w'), indent=2)
PY
xray run -test -config /usr/local/etc/xray/config.json 2>&1 | tail -1

log "5/6 сеть и логи"
grep -q 'tcp_congestion_control' /etc/sysctl.conf || cat >> /etc/sysctl.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.netfilter.nf_conntrack_max=131072
net.core.somaxconn=8192
EOF
sysctl -p >/dev/null 2>&1 || true
cat > /etc/logrotate.d/xray <<'EOF'
/var/log/xray/*.log { daily rotate 3 compress missingok notifempty copytruncate }
EOF
# Часть хостеров отдаёт образ с включённым ufw, где открыты только 22, 80 и 443:
# 8443 снаружи молчит, а самопроверка через loopback этого не видит.
if ufw status 2>/dev/null | grep -q '^Status: active'; then
  ufw allow 443/tcp >/dev/null && ufw allow 8443/tcp >/dev/null && log "    ufw: открыл 443 и 8443"
fi
if systemctl is-active --quiet firewalld 2>/dev/null; then
  firewall-cmd -q --permanent --add-port=443/tcp --add-port=8443/tcp && firewall-cmd -q --reload \
    && log "    firewalld: открыл 443 и 8443"
fi
# Логи должны принадлежать пользователю службы (обычно nobody). Установщик
# создаёт их так только при первой установке; если файлов не было, их создал
# от root наш же `xray run -test` на шаге 4 — и служба падает
# с «access.log: permission denied». Права — как ставит сам установщик.
SVC_USER=$(systemctl show -p User --value xray 2>/dev/null || true)
mkdir -p /var/log/xray && chown 0:0 /var/log/xray && chmod 755 /var/log/xray
touch /var/log/xray/access.log /var/log/xray/error.log
if [ -n "$SVC_USER" ] && id "$SVC_USER" >/dev/null 2>&1; then
  chown "$SVC_USER": /var/log/xray/*.log && chmod 600 /var/log/xray/*.log
fi
systemctl restart xray; sleep 3
# restart отвечает успехом, даже если Xray тут же упал, — спрашиваем отдельно.
systemctl is-active --quiet xray || {
  journalctl -u xray -n 20 --no-pager -o cat 2>/dev/null | grep -v '^$' | tail -3; echo "ERROR=service"; exit 2; }

log "6/6 самопроверка — реальный хэндшейк через loopback"
cat > /root/.verify.json <<EOF
{"log":{"loglevel":"warning"},
 "inbounds":[{"listen":"127.0.0.1","port":10809,"protocol":"socks","settings":{"udp":true}}],
 "outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":443,
   "users":[{"id":"$UUID","encryption":"none","flow":"xtls-rprx-vision"}]}]},
   "streamSettings":{"network":"tcp","security":"reality","realitySettings":{
     "serverName":"$DEST","fingerprint":"edge","publicKey":"$PUB","shortId":"$SID"}}}]}
EOF
setsid nohup xray run -config /root/.verify.json >/dev/null 2>&1 </dev/null &
sleep 4
# Второй адрес — на случай, если первый сервис недоступен из страны сервера.
OUT=""
for u in https://api.ipify.org https://icanhazip.com; do
  OUT=$(curl -s --max-time 20 --socks5-hostname 127.0.0.1:10809 "$u" | tr -d '[:space:]' || true)
  [ -n "$OUT" ] && break
done
for p in $(ss -tlnp 2>/dev/null | grep 10809 | grep -oP 'pid=\K[0-9]+'); do kill $p 2>/dev/null || true; done
rm -f /root/.verify.json

echo
if [ -n "$OUT" ]; then
  echo "=== ПРОКСИ РАБОТАЕТ, выходной IP: $OUT ==="
else
  echo "=== САМОПРОВЕРКА НЕ ПРОШЛА — конфиг оставлен для разбора ==="
  tail -3 /var/log/xray/error.log 2>/dev/null || true
  echo "ERROR=selfcheck"; exit 1
fi
echo "UUID=$UUID"
echo "PUBLIC_KEY=$PUB"
echo "SHORT_ID=$SID"
echo "DEST=$DEST"
