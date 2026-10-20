# Issues the certificate for one domain, answering HTTP-01 from the webroot
# nginx serves, and links it like a renewal would.
set -eu
certbot certonly --non-interactive --quiet --agree-tos --keep-until-expiring \
	{{with .Email}}--email {{q .}}{{else}}--register-unsafely-without-email{{end}} \
	--webroot --webroot-path {{.ACMEDir}} --cert-name {{q .Domain}} --domains {{q .Domain}}
RENEWED_LINEAGE=/etc/letsencrypt/live/{{q .Domain}} {{.Hook}}
