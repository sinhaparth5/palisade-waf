#!/bin/sh
# Synthetic traffic for the public demo: browsing from a few countries plus
# the attacks Palisade stops. The WAF trusts this container's
# X-Forwarded-For (--trusted-proxies 172.30.0.10 in compose.yml).
W=http://waf:8080
UA='Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0'
# US DE NL IN JP BR AU GB CA NG CN (cloud and ISP ranges)
VISITORS='3.80.0.10 88.198.0.10 51.15.0.10 13.232.0.10 13.112.0.10 18.228.0.10 13.236.0.10 35.176.0.10 52.60.0.10 41.203.64.10 1.12.0.10'
ATTACKER=185.220.101.10 # keeps attacking until autoban stops it
# Other attacks come from random 185.220.101.0/24 addresses (DE), each rarely
# reused, so they show as WAF blocks without banning the visitors above.
BLOCKED=5.255.255.10    # RU: seed.json blocks the country

hit() { # ip path [curl args]
	ip=$1 path=$2
	shift 2
	curl -s -o /dev/null -m 5 --path-as-is -H "X-Forwarded-For: $ip" -A "$UA" \
		-H 'Accept: text/html' -H 'Accept-Language: en-US,en' "$@" "$W$path" || true
}
rnd() { echo $(($(od -An -N2 -tu2 /dev/urandom) % $1)); }
pick() {
	set -- $1
	shift "$(rnd $#)"
	echo "$1"
}

until curl -sf -o /dev/null "$W/_cz/readyz"; do sleep 2; done
while :; do
	for p in / /index.html /?page=2 /50x.html /index.html?ref=news; do
		hit "$(pick "$VISITORS")" "$p"
		sleep 1
	done
	ip=185.220.101.$(($(rnd 240) + 11))
	case $(rnd 6) in
	0) hit "$ip" "/products?id=1%27%20OR%20%271%27%3D%271" ;;
	1) hit "$ip" "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E" ;;
	2) hit "$ip" "/download?file=../../../../etc/passwd" ;;
	3) hit "$ip" /wp-login.php -A 'sqlmap/1.8.4#stable (https://sqlmap.org)' ;;
	4) hit "$BLOCKED" / ;;
	5) for _ in $(seq 40); do hit "$ip" /; done ;; # over the 5 rps limit
	esac
	hit "$ATTACKER" "/.env"
	hit "$ATTACKER" "/?id=1%20UNION%20SELECT%20password%20FROM%20users"
done
