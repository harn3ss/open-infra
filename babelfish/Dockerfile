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
	gnupg unixodbc-dev net-tools unzip wget

WORKDIR /workplace
ENV BABELFISH_URL=https://github.com/babelfish-for-postgresql/babelfish-for-postgresql
RUN wget -q ${BABELFISH_URL}/releases/download/${BABELFISH_VERSION}/${BABELFISH_VERSION}.tar.gz \
	&& tar -xzf ${BABELFISH_VERSION}.tar.gz

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

# --- Babelfish extensions ---
RUN cp /usr/local/lib/libantlr4-runtime.so.${ANTLR4_VERSION} ${BABELFISH_HOME}/lib
# FindANTLR.cmake needs Java (to run the parser generator) + the antlr4 runtime headers.
ENV ANTLR4_JAVA_BIN=/usr/bin/java
ENV ANTLR4_RUNTIME_LIBRARIES=/usr/include/antlr4-runtime
WORKDIR ${PG_SRC}/contrib/babelfishpg_tsql/antlr
RUN cmake -Wno-dev . && make all
WORKDIR ${PG_SRC}/contrib/babelfishpg_common
RUN make -j ${JOBS} && make PG_CONFIG=${PG_CONFIG} install
WORKDIR ${PG_SRC}/contrib/babelfishpg_money
RUN make -j ${JOBS} && make PG_CONFIG=${PG_CONFIG} install
WORKDIR ${PG_SRC}/contrib/babelfishpg_tds
RUN make -j ${JOBS} && make PG_CONFIG=${PG_CONFIG} install
WORKDIR ${PG_SRC}/contrib/babelfishpg_tsql
RUN make -j ${JOBS} && make PG_CONFIG=${PG_CONFIG} install

# ---------------------------------------------------------------------------- runtime
FROM base AS runner
ENV DEBIAN_FRONTEND=noninteractive
ENV BABELFISH_HOME=/opt/babelfish
ENV POSTGRES_USER_HOME=/var/lib/babelfish
ENV BABELFISH_DATA=${POSTGRES_USER_HOME}/data
EXPOSE 1433 5432

# apt upgrade patches the fixable base-image CVEs; only runtime libs are installed.
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
	libssl3 openssl libldap-2.5-0 libxml2 libpam0g uuid libossp-uuid16 \
	libxslt1.1 libicu70 libpq5 unixodbc \
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
