#!/bin/bash
# VLESS + Reality на Xray. Идемпотентно: можно гонять повторно.
set -eu

log(){ echo "[$(date +%H:%M:%S)] $*"; }

log "1/6 установка Xray"
if ! command -v xray >/dev/null 2>&1; then
  bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install >/dev/null 2>&1
fi
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
systemctl restart xray; sleep 3

log "6/6 самопроверка — реальный хэндшейк через loopback"
cat > /root/.verify.json <<EOF
{"log":{"loglevel":"warning"},
 "inbounds":[{"listen":"127.0.0.1","port":10809,"protocol":"socks","settings":{"udp":true}}],
 "outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":443,
   "users":[{"id":"$UUID","encryption":"none","flow":"xtls-rprx-vision"}]}]},
   "streamSettings":{"network":"tcp","security":"reality","realitySettings":{
     "serverName":"$DEST","fingerprint":"chrome","publicKey":"$PUB","shortId":"$SID"}}}]}
EOF
setsid nohup xray run -config /root/.verify.json >/dev/null 2>&1 </dev/null &
sleep 4
OUT=$(curl -s --max-time 20 --socks5-hostname 127.0.0.1:10809 https://api.ipify.org || true)
for p in $(ss -tlnp 2>/dev/null | grep 10809 | grep -oP 'pid=\K[0-9]+'); do kill $p 2>/dev/null || true; done
rm -f /root/.verify.json

echo
if [ -n "$OUT" ]; then
  echo "=== ПРОКСИ РАБОТАЕТ, выходной IP: $OUT ==="
else
  echo "=== САМОПРОВЕРКА НЕ ПРОШЛА — конфиг оставлен для разбора ==="; exit 1
fi
echo "UUID=$UUID"
echo "PUBLIC_KEY=$PUB"
echo "SHORT_ID=$SID"
echo "DEST=$DEST"
