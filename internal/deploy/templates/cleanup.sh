set -eu
for dir in {{q .Root}}/*; do
	[ "$dir" = {{q .Keep}} ] || rm -rf "$dir"
done
if command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then
	want='{{range .Ports}} {{.}}{{end}} '
	ufw status numbered | sed -n 's|^\[ *\([0-9]*\)\] \([0-9]*/[a-z]*\) .*# princo$|\1 \2|p' | sort -rn | while read -r n r; do
		case "$want" in *" $r "*) ;; *) ufw --force delete "$n" >/dev/null ;; esac
	done
fi
