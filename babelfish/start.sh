#!/bin/sh
# open-infra Babelfish entrypoint — the upstream community init, plus optional TLS on
# the TDS (1433) + Postgres (5432) listeners when a cert is mounted. Babelfish's TDS
# listener honours Postgres's ssl GUCs, so enabling `ssl` encrypts both protocols.
BABELFISH_HOME=/opt/babelfish
BABELFISH_DATA=/var/lib/babelfish/data

cd ${BABELFISH_HOME}/bin

# Defaults (overridden by -u/-p/-d/-m).
USERNAME=babelfish_user
PASSWORD=12345678
DATABASE=babelfish_db
MIGRATION_MODE=single-db

while getopts u:p:d:m: flag; do
	case "${flag}" in
		u) USERNAME=${OPTARG};;
		p) PASSWORD=${OPTARG};;
		d) DATABASE=${OPTARG};;
		m) MIGRATION_MODE=${OPTARG};;
	esac
done

# First-boot init (unchanged from upstream).
if [ ! -f ${BABELFISH_DATA}/postgresql.conf ]; then
	./initdb -D ${BABELFISH_DATA}/ -E "UTF8"
	cat <<- EOF >> ${BABELFISH_DATA}/pg_hba.conf
		# Allow all connections
		host	all		all		0.0.0.0/0		md5
		host	all		all		::0/0				md5
	EOF
	cat <<- EOF >> ${BABELFISH_DATA}/postgresql.conf
		listen_addresses = '*'
		allow_system_table_mods = on
		shared_preload_libraries = 'babelfishpg_tds'
		babelfishpg_tds.listen_addresses = '*'
		babelfishpg_tsql.migration_mode = '${MIGRATION_MODE}'
	EOF
	./pg_ctl -D ${BABELFISH_DATA}/ start
	./psql -c "ALTER USER postgres WITH PASSWORD '${PASSWORD}';"
	./psql -c "CREATE USER ${USERNAME} WITH SUPERUSER CREATEDB CREATEROLE PASSWORD '${PASSWORD}' INHERIT;" \
		-c "DROP DATABASE IF EXISTS ${DATABASE};" \
		-c "CREATE DATABASE ${DATABASE} OWNER ${USERNAME};" \
		-c "\c ${DATABASE}" \
		-c "CREATE EXTENSION IF NOT EXISTS \"babelfishpg_tds\" CASCADE;" \
		-c "GRANT ALL ON SCHEMA sys to ${USERNAME};" \
		-c "ALTER USER ${USERNAME} CREATEDB;" \
		-c "ALTER SYSTEM SET babelfishpg_tsql.database_name = '${DATABASE}';" \
		-c "SELECT pg_reload_conf();"
	./psql -d ${DATABASE} \
		-c "CALL SYS.INITIALIZE_BABELFISH('${USERNAME}');"
	./pg_ctl -D ${BABELFISH_DATA}/ stop
else
	# open-infra: reconcile the app + superuser password to the injected secret on every
	# (non-first) boot. This makes the Kubernetes Secret authoritative — a data dir RESTORED
	# from a snapshot carries the SOURCE database's password, but a restored instance gets its
	# own freshly-generated secret; without this, its connection secret wouldn't authenticate.
	# Idempotent: a no-op when they already match (the normal case). Best-effort.
	./pg_ctl -D ${BABELFISH_DATA}/ -w start
	./psql -c "ALTER USER postgres WITH PASSWORD '${PASSWORD}';" || true
	./psql -c "ALTER USER ${USERNAME} WITH PASSWORD '${PASSWORD}';" || true
	./pg_ctl -D ${BABELFISH_DATA}/ -w stop
fi

# --- open-infra: enable TLS when a cert is mounted (BABELFISH_TLS_DIR with tls.crt/tls.key).
# Postgres requires the key to be 0600 and owned by the run user, so copy it into PGDATA.
# Idempotent — the marked block is stripped and rewritten on every boot.
if [ -n "${BABELFISH_TLS_DIR}" ] && [ -f "${BABELFISH_TLS_DIR}/tls.crt" ] && [ -f "${BABELFISH_TLS_DIR}/tls.key" ]; then
	cp "${BABELFISH_TLS_DIR}/tls.crt" "${BABELFISH_DATA}/server.crt"
	cp "${BABELFISH_TLS_DIR}/tls.key" "${BABELFISH_DATA}/server.key"
	chmod 0600 "${BABELFISH_DATA}/server.key"
	chmod 0644 "${BABELFISH_DATA}/server.crt"
	sed -i '/# openinfra-tls-begin/,/# openinfra-tls-end/d' "${BABELFISH_DATA}/postgresql.conf"
	cat <<- EOF >> ${BABELFISH_DATA}/postgresql.conf
		# openinfra-tls-begin
		ssl = on
		ssl_cert_file = 'server.crt'
		ssl_key_file = 'server.key'
		# openinfra-tls-end
	EOF
	echo "openinfra: TLS enabled on TDS/PG listeners (cert from ${BABELFISH_TLS_DIR})"
fi

exec ./postgres -D ${BABELFISH_DATA}/ -i
