FROM ubuntu:22.04

RUN apt-get update && apt-get install --no-install-recommends -y \
    python3 python3-uvloop python3-cryptography python3-socks libcap2-bin ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Gán quyền CAP_NET_BIND_SERVICE vào file thực sự của python3
RUN setcap cap_net_bind_service=+ep $(readlink -f /usr/bin/python3)

RUN useradd tgproxy -u 10000

USER tgproxy

WORKDIR /home/tgproxy/

COPY --chown=tgproxy mtprotoproxy.py config.py init.sh /home/tgproxy/

# Ensure config.py has write permissions and init script is executable
USER root
RUN chmod 666 /home/tgproxy/config.py && chmod +x /home/tgproxy/init.sh
USER tgproxy

CMD ["./init.sh"]
