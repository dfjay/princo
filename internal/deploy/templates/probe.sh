# Prints "<key> <value>" lines.
set -eu
. /etc/os-release
case " ${ID:-} ${ID_LIKE:-} " in
*" debian "* | *" ubuntu "*) ;;
*)
	echo "princo deploy needs Debian or Ubuntu; this is ${PRETTY_NAME:-${ID:-an unknown system}}" >&2
	exit 1
	;;
esac
echo "arch $(dpkg --print-architecture)"
if [ -f {{.StateFile}} ]; then
	echo "node $(sed -n 's/.*"node":"\([^"]*\)".*/\1/p' {{.StateFile}})"
fi
if command -v princo >/dev/null; then
	echo "princo $(princo version | cut -d' ' -f2)"
fi
{{- range .Certificates}}
[ -s {{q (print $.CertDir "/" . "/fullchain.pem")}} ] || echo missing {{q .}}
{{- end}}
