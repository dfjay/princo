set -eu
export DEBIAN_FRONTEND=noninteractive
{{- with .Repo}}
install -d -m 0755 /etc/apt/keyrings
cat >/etc/apt/keyrings/{{.Name}}.asc <<'PRINCO_EOF'
{{.Key}}
PRINCO_EOF
cat >/etc/apt/sources.list.d/{{.Name}}.sources <<'PRINCO_EOF'
{{.Sources -}}
PRINCO_EOF
{{- end}}
missing=
for p in{{range .Packages}} {{q .}}{{end}}; do
	dpkg-query -W -f '${Status}' "$p" 2>/dev/null | grep -q 'ok installed' || missing="$missing $p"
done
if [ -n "$missing" ]; then
	apt-get update -q
	apt-get install -y -q $missing
fi
{{- with .PackageUnit}}
# princo.service runs the engine instead.
systemctl disable --now {{q .}} >/dev/null 2>&1 || true
{{- end}}
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
