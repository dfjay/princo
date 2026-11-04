set -eu
for dir in {{q .Root}}/*; do
	[ "$dir" = {{q .Keep}} ] || rm -rf "$dir"
done
for dir in {{q .LegoRoot}}/*; do
	[ "$dir" = {{q .KeepLego}} ] || rm -rf "$dir"
done
if ! [ -e {{q .LegoTimer}} ]; then
	systemctl disable --now --quiet princo-lego.timer 2>/dev/null || true
fi
if command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then
	want='{{range .Ports}} {{.}}{{end}} '
	ufw status numbered | sed -n 's|^\[ *\([0-9]*\)\] \([0-9]*/[a-z]*\) .*# princo$|\1 \2|p' | sort -rn | while read -r n r; do
		case "$want" in *" $r "*) ;; *) ufw --force delete "$n" >/dev/null ;; esac
	done
fi
