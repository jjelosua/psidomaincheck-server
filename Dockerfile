FROM tiangolo/uvicorn-gunicorn:python3.8

LABEL maintainer="Juan Elosua <juan.elosua@gmail.com>"

RUN apt update
# Can't use debian package since libsodium for buster is 1.0.17 and does not include ristretto.
# compiling from sources
RUN curl https://download.libsodium.org/libsodium/releases/libsodium-1.0.18-stable.tar.gz --output /tmp/libsodium-1.0.18-stable.tar.gz
WORKDIR /tmp
RUN tar xvf libsodium-1.0.18-stable.tar.gz
WORKDIR /tmp/libsodium-stable
RUN ./configure
RUN make && make check
RUN make install
# We need to run ldconfig in order for the system to find libsodium. via https://github.com/jedisct1/minisign/issues/67
RUN ldconfig

COPY server-requirements.txt /tmp/
RUN pip install --no-cache-dir -r /tmp/server-requirements.txt

# COPY ./app /app
WORKDIR /app
CMD ["/start-reload.sh"]
