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
if [ -e {{.StreamConf}} ]; then
	echo stream
fi
[ -x {{q .Engine}} ] && echo engine
[ -x {{q .Lego}} ] && echo lego
command -v openssl >/dev/null && echo openssl
if command -v princo >/dev/null; then
	echo "princo $(princo version | cut -d' ' -f2)"
fi
{{- range .Certificates}}
chain={{q (print $.CertDir "/" .Name "/fullchain.pem")}} key={{q (print $.CertDir "/" .Name "/key.pem")}}
# One the last bundle brought goes with it.
if ! [ -s "$chain" ] || ! [ -s "$key" ] || grep -qsF "\"$key\"" {{$.StateFile}}; then
	echo missing {{q .Name}}
elif [ -L "$key" ]; then
	echo linked {{q .Name}}
elif command -v openssl >/dev/null; then
	echo sans {{q .Name}} "$(openssl x509 -noout -ext subjectAltName -in "$chain" 2>/dev/null | tail -n +2 | tr -d ' \n')"
fi
{{- end}}
