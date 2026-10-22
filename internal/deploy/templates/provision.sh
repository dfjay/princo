set -eu
export DEBIAN_FRONTEND=noninteractive
missing=
for p in{{range .Packages}} {{q .}}{{end}}; do
	dpkg-query -W -f '${Status}' "$p" 2>/dev/null | grep -q 'ok installed' || missing="$missing $p"
done
if [ -n "$missing" ]; then
	apt-get update -q
	apt-get install -y -q $missing
fi
getent group {{.Group}} >/dev/null || groupadd --system {{.Group}}
if command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then
	allows() { ufw status | grep -Eq "^$1 +ALLOW( IN)? +Anywhere"; }
	for r in{{range .Ports}} {{.}}{{end}}; do
		# Tagged for cleanup.sh; a family the host already allows keeps its rule.
		port=${r%/*} proto=${r#*/}
		if ! allows "$r" && ! allows "$r \(v6\)"; then
			ufw allow "$r" comment princo >/dev/null
		elif ! allows "$r"; then
			ufw allow proto "$proto" from 0.0.0.0/0 to any port "$port" comment princo >/dev/null
		elif ! allows "$r \(v6\)" && grep -qs '^IPV6=yes' /etc/default/ufw; then
			ufw allow proto "$proto" from ::/0 to any port "$port" comment princo >/dev/null
		fi
	done
fi
