FROM alpine:3.4
MAINTAINER Antoni Segura Puimedon "toni@kuryr.org"
WORKDIR /
COPY . /opt/kuryr-libnetwork
RUN \
  apk add --no-cache \
    bash \
    iproute2 \
    openvswitch \
    py-pip \
    python \
    uwsgi-python \
  && apk add --no-cache --virtual build-deps \
      gcc \
      git \
      linux-headers \
      musl-dev \
      python-dev \
  && pip install -U pip setuptools \
  \
  && cd /opt/kuryr-libnetwork \
  && pip install . \
  && cd / \
  && apk del build-deps

ENV SERVICE_USER="admin"
ENV SERVICE_PROJECT_NAME="admin"
ENV SERVICE_PASSWORD="pass"
ENV SERVICE_DOMAIN_NAME="Default"
ENV USER_DOMAIN_NAME="Default"
ENV IDENTITY_URL="http://127.0.0.1:35357/v3"
ENV CAPABILITY_SCOPE="local"
ENV LOG_LEVEL="INFO"
ENV PROCESSES=2
ENV THREADS=2

VOLUME /var/log/kuryr

CMD ["/opt/kuryr-libnetwork/contrib/docker/run_kuryr.sh"]
