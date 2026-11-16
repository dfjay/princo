set -eu
for dir in {{q .Root}}/*; do
	[ "$dir" = {{q .Keep}} ] || rm -rf "$dir"
done
for dir in {{q .LegoRoot}}/*; do
	[ "$dir" = {{q .KeepLego}} ] || rm -rf "$dir"
done
{{- range .Certificates}}
{{- if eq .Group "root"}}
# The engine may have served it before.
dir={{q (print $.CertDir "/" .Name)}}
if [ -f "$dir/key.pem" ]; then
	chgrp root "$dir" "$dir/fullchain.pem" "$dir/key.pem"
fi
{{- end}}
{{- end}}
if ! [ -e {{q .LegoTimer}} ]; then
	systemctl disable --now --quiet princo-lego.timer 2>/dev/null || true
fi
if ! [ -e {{q .MonitorTimer}} ]; then
	systemctl disable --now --quiet princo-monitor.timer 2>/dev/null || true
	# A run under way would write the state again.
	systemctl stop --quiet princo-monitor.service 2>/dev/null || true
	# Under the lock of a run someone started by hand.
	flock {{q .StateDir}} rm -f {{q .MonitorState}}
fi
if command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then
	want='{{range .Ports}} {{.}}{{end}} '
	ufw status numbered | sed -n 's|^\[ *\([0-9]*\)\] \([0-9]*/[a-z]*\) .*# princo$|\1 \2|p' | sort -rn | while read -r n r; do
		case "$want" in *" $r "*) ;; *) ufw --force delete "$n" >/dev/null ;; esac
	done
fi
