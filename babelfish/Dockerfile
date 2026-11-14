# open-infra's first-party Babelfish for PostgreSQL image — built FROM SOURCE.
#
# Multi-stage: `builder` compiles the Babelfish fork of PostgreSQL + its extensions
# (ANTLR-generated T-SQL parser, babelfishpg_{common,money,tds,tsql}); `runner` ships
# only the runtime libraries + our TLS-capable start.sh. We build it ourselves (rather
# than deriving from a community image) so we control the base and apply OS security
# patches — `apt upgrade` clears the fixable base-image CVEs the prebuilt image carried.
#
# Bump BABELFISH_VERSION deliberately (tags: github.com/babelfish-for-postgresql).
FROM ubuntu:22.04 AS base

# ---------------------------------------------------------------------------- build
FROM base AS builder
ARG BABELFISH_VERSION=BABEL_5_4_0__PG_17_7
# Optional: build from two pinned commits instead of a release tarball, for a Babelfish line the
# project ships as a stable branch but not as a release (e.g. 4.9 on PostgreSQL 16.13, which Aurora
# runs). Both must be full commit SHAs: the PostgreSQL fork and babelfish_extensions.
ARG BABELFISH_PG_COMMIT=
ARG BABELFISH_EXT_COMMIT=
ENV DEBIAN_FRONTEND=noninteractive
ENV JOBS=8

RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
	build-essential flex libxml2-dev libxml2-utils \
	libxslt-dev libssl-dev libreadline-dev zlib1g-dev \
	libldap2-dev libpam0g-dev gettext uuid uuid-dev \
	cmake lld apt-utils libossp-uuid-dev gnulib bison \
	xsltproc icu-devtools libicu70 \
	libicu-dev gawk \
	curl openjdk-21-jre openssl \
	g++ python-dev-is-python3 libpq-dev \
	pkg-config libutfcpp-dev \
	gnupg unixodbc-dev net-tools unzip wget \
	libgeos-dev libproj-dev libjson-c-dev

WORKDIR /workplace
ENV BABELFISH_URL=https://github.com/babelfish-for-postgresql/babelfish-for-postgresql
ENV BABELFISH_ORG=https://github.com/babelfish-for-postgresql
RUN if [ -n "${BABELFISH_PG_COMMIT}" ]; then \
		echo "${BABELFISH_PG_COMMIT}${BABELFISH_EXT_COMMIT}" | grep -Eq '^[0-9a-f]{80}$' \
		&& wget -q -O pg.tar.gz ${BABELFISH_ORG}/postgresql_modified_for_babelfish/archive/${BABELFISH_PG_COMMIT}.tar.gz \
		&& wget -q -O ext.tar.gz ${BABELFISH_ORG}/babelfish_extensions/archive/${BABELFISH_EXT_COMMIT}.tar.gz \
		&& mkdir -p ${BABELFISH_VERSION} ext \
		&& tar -xzf pg.tar.gz --strip-components=1 -C ${BABELFISH_VERSION} \
		&& tar -xzf ext.tar.gz --strip-components=1 -C ext \
		&& cp -r ext/contrib/babelfishpg_common ext/contrib/babelfishpg_money ext/contrib/babelfishpg_tds ext/contrib/babelfishpg_tsql ${BABELFISH_VERSION}/contrib/ \
		&& rm -rf ext pg.tar.gz ext.tar.gz; \
	else \
		wget -q ${BABELFISH_URL}/releases/download/${BABELFISH_VERSION}/${BABELFISH_VERSION}.tar.gz \
		&& tar -xzf ${BABELFISH_VERSION}.tar.gz; \
	fi

ENV BABELFISH_HOME=/opt/babelfish
ENV PG_CONFIG=${BABELFISH_HOME}/bin/pg_config
ENV PG_SRC=/workplace/${BABELFISH_VERSION}

# --- ANTLR4 (parser generator jar + C++ runtime) ---
ENV ANTLR4_VERSION=4.13.2
ENV ANTLR_FILE=antlr-${ANTLR4_VERSION}-complete.jar
ENV ANTLR_EXECUTABLE=/usr/local/lib/${ANTLR_FILE}
ENV ANTLR_RUNTIME=/workplace/antlr4
RUN cp ${PG_SRC}/contrib/babelfishpg_tsql/antlr/thirdparty/antlr/${ANTLR_FILE} /usr/local/lib
WORKDIR /workplace
RUN wget -q http://www.antlr.org/download/antlr4-cpp-runtime-${ANTLR4_VERSION}-source.zip \
	&& unzip -q -d ${ANTLR_RUNTIME} antlr4-cpp-runtime-${ANTLR4_VERSION}-source.zip
WORKDIR ${ANTLR_RUNTIME}/build
RUN cmake .. -DANTLR_JAR_LOCATION=${ANTLR_EXECUTABLE} -DCMAKE_INSTALL_PREFIX=/usr/local -DWITH_DEMO=True \
	&& make -j ${JOBS} && make install

# --- modified PostgreSQL for Babelfish ---
WORKDIR ${PG_SRC}
RUN ./configure CFLAGS="-ggdb" --prefix=${BABELFISH_HOME}/ --enable-debug \
	--with-ldap --with-libxml --with-pam --with-uuid=ossp --enable-nls \
	--with-libxslt --with-icu --with-openssl \
	&& make DESTDIR=${BABELFISH_HOME}/ -j ${JOBS} && make install
WORKDIR ${PG_SRC}/contrib
RUN make -j ${JOBS} && make install

# --- PostGIS: Babelfish's geography and geometry types call into its library ($libdir/postgis-3),
# as Babelfish's own CI builds them (PostGIS 3.5.1, no raster, no protobuf). Checksum-pinned.
ENV POSTGIS_VERSION=3.5.1
ENV POSTGIS_SHA256=23706abc117fb1bab45a27a263b589f52fc08ebaff318c0bc0bdc940905306b5
WORKDIR /workplace
RUN wget -q https://download.osgeo.org/postgis/source/postgis-${POSTGIS_VERSION}.tar.gz \
	&& echo "${POSTGIS_SHA256}  postgis-${POSTGIS_VERSION}.tar.gz" | sha256sum -c - \
	&& tar -xzf postgis-${POSTGIS_VERSION}.tar.gz \
	&& cd postgis-${POSTGIS_VERSION} \
	&& ./configure --without-protobuf --without-raster --with-pgconfig=${PG_CONFIG} \
	&& make -j ${JOBS} && make install

# --- Babelfish extensions ---
RUN cp /usr/local/lib/libantlr4-runtime.so.${ANTLR4_VERSION} ${BABELFISH_HOME}/lib
# FindANTLR.cmake needs Java (to run the parser generator) + the antlr4 runtime headers.
ENV ANTLR4_JAVA_BIN=/usr/bin/java
ENV ANTLR4_RUNTIME_LIBRARIES=/usr/include/antlr4-runtime
WORKDIR ${PG_SRC}/contrib/babelfishpg_tsql/antlr
RUN cmake -Wno-dev . && make all
WORKDIR ${PG_SRC}/contrib/babelfishpg_common
RUN PG_CPPFLAGS='-DENABLE_SPATIAL_TYPES' make -j ${JOBS} && PG_CPPFLAGS='-DENABLE_SPATIAL_TYPES' make PG_CONFIG=${PG_CONFIG} install
WORKDIR ${PG_SRC}/contrib/babelfishpg_money
RUN PG_CPPFLAGS='-DENABLE_SPATIAL_TYPES' make -j ${JOBS} && PG_CPPFLAGS='-DENABLE_SPATIAL_TYPES' make PG_CONFIG=${PG_CONFIG} install
WORKDIR ${PG_SRC}/contrib/babelfishpg_tds
RUN PG_CPPFLAGS='-DENABLE_SPATIAL_TYPES' make -j ${JOBS} && PG_CPPFLAGS='-DENABLE_SPATIAL_TYPES' make PG_CONFIG=${PG_CONFIG} install
WORKDIR ${PG_SRC}/contrib/babelfishpg_tsql
RUN PG_CPPFLAGS='-DENABLE_SPATIAL_TYPES' make -j ${JOBS} && PG_CPPFLAGS='-DENABLE_SPATIAL_TYPES' make PG_CONFIG=${PG_CONFIG} install

# ---------------------------------------------------------------------------- runtime
FROM base AS runner
# not a Go build — carries no image-level FIPS claim
LABEL openinfra.dev/fips=false
ENV DEBIAN_FRONTEND=noninteractive
ENV BABELFISH_HOME=/opt/babelfish
ENV POSTGRES_USER_HOME=/var/lib/babelfish
ENV BABELFISH_DATA=${POSTGRES_USER_HOME}/data
EXPOSE 1433 5432

# apt upgrade patches the fixable base-image CVEs; only runtime libs are installed.
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
	libssl3 openssl libldap-2.5-0 libxml2 libpam0g uuid libossp-uuid16 \
	libxslt1.1 libicu70 libpq5 unixodbc \
	libgeos-c1v5 libproj22 libjson-c5 \
	&& apt-get clean && rm -rf /var/lib/apt/lists/*

RUN adduser postgres --home ${POSTGRES_USER_HOME}
COPY start.sh /start.sh
RUN chmod 0755 /start.sh
WORKDIR ${BABELFISH_HOME}
COPY --from=builder --chown=postgres ${BABELFISH_HOME} .
RUN install -d -o postgres -g postgres ${BABELFISH_DATA}
VOLUME ${BABELFISH_DATA}

USER postgres
ENTRYPOINT ["/start.sh"]
