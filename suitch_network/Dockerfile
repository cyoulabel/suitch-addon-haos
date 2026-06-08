FROM python:3.12-alpine

# Evitar segfault de OpenSSL en Alpine
RUN apk add --no-cache ca-certificates openssl libssl3 libcrypto3

WORKDIR /app
COPY run.sh /run.sh
COPY suitch.py /app/suitch.py

RUN chmod +x /run.sh

CMD ["/run.sh"]
