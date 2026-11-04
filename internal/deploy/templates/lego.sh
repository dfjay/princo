#!/bin/sh
# Written by princo deploy; changes here are overwritten.
# Issues or renews the named DNS-01 certificates, or all, when due.
set -eu
[ $# -gt 0 ] || set --{{range .Certificates}} {{q .Name}}{{end}}
# lego runs the hook only when it issues: restores a copy gone missing.
restore() {
	[ -s {{$.CertDir}}/"$1"/key.pem ] && return 0
	[ -s {{$.Dir}}/certificates/"$1".key ] || return 0
	LEGO_HOOK_CERT_NAME=$1 \
		LEGO_HOOK_CERT_PATH={{$.Dir}}/certificates/"$1".crt \
		LEGO_HOOK_CERT_KEY_PATH={{$.Dir}}/certificates/"$1".key \
		{{$.Hook}}
}
status=0
for name; do
	case "$name" in
{{- range .Certificates}}
	{{q .Name}})
		{{q $.Lego}} run --path {{$.Dir}} --accept-tos{{with $.Email}} --email {{q .}}{{end}} \
			--dns {{q .DNS}} --env-file {{q (call $.Env .Name)}} \
			--cert.name {{q .Name}}{{range .Domains}} --domains {{q .}}{{end}} --force-cert-domains \
			--deploy-hook {{$.Hook}} || status=1
		restore {{q .Name}} || status=1
		;;
{{- end}}
	*)
		echo "princo-lego: no certificate $name" >&2
		status=1
		;;
	esac
done
exit $status
