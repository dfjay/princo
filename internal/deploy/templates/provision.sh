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
	for r in{{range .Ports}} {{.}}{{end}}; do
		# Tagged for cleanup.sh, unless the host already allows it.
		ufw status | grep -Eq "^$r( \(v6\))? +ALLOW( IN)? +Anywhere" || ufw allow "$r" comment princo >/dev/null
	done
fi
