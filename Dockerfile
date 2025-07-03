FROM alpine:3.18

LABEL maintainer="Antoni Segura Puimedon <toni@kuryr.org>"

WORKDIR /

COPY . /opt/kuryr-libnetwork

RUN set -ex && \
    apk add --no-cache \
        bash \
        iproute2 \
        openvswitch \
        py3-pip \
        python3 \
        uwsgi-python3 \
    && apk add --no-cache --virtual build-deps \
        gcc \
        git \
        linux-headers \
        musl-dev \
        python3-dev \
    && pip3 install --upgrade pip setuptools \
    && cd /opt/kuryr-libnetwork \
    && pip3 install . \
    && cd / \
    && apk del build-deps \
    && rm -rf /root/.cache /var/cache/apk/*

# Environment variables (can be overridden at runtime)
ENV SERVICE_USER="admin" \
    SERVICE_PROJECT_NAME="admin" \
    SERVICE_PASSWORD="pass" \
    SERVICE_DOMAIN_NAME="Default" \
    USER_DOMAIN_NAME="Default" \
    IDENTITY_URL="http://127.0.0.1:5000/v3" \
    CAPABILITY_SCOPE="local" \
    HTTP_SOCKET=":23750" \
    LOG_LEVEL="INFO" \
    PROCESSES=2

VOLUME /var/log/kuryr

CMD ["/opt/kuryr-libnetwork/contrib/docker/run_kuryr.sh"]