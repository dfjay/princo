set -eu
certbot certonly --non-interactive --quiet --agree-tos --keep-until-expiring \
	{{with .Email}}--email {{q .}}{{else}}--register-unsafely-without-email{{end}} \
	--webroot --webroot-path {{.ACMEDir}} --cert-name {{q .Name}} --domains {{q .Domains}}
RENEWED_LINEAGE=/etc/letsencrypt/live/{{q .Name}} {{.Hook}}
