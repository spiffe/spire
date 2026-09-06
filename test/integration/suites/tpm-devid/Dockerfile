FROM debian:12-slim AS swtpm

RUN apt-get update \
    && apt-get install -y --no-install-recommends swtpm \
    && rm -rf /var/lib/apt/lists/*

COPY swtpm-entrypoint.sh /usr/local/bin/swtpm-entrypoint.sh
RUN chmod +x /usr/local/bin/swtpm-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/swtpm-entrypoint.sh"]
