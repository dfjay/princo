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
{{- if or .TCP .UDP}}
if command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then
{{- range .TCP}}
	ufw allow {{.}}/tcp >/dev/null
{{- end}}
{{- range .UDP}}
	ufw allow {{.}}/udp >/dev/null
{{- end}}
fi
{{- end}}
