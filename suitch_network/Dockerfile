FROM python:3.12-alpine

RUN apk add --no-cache ca-certificates

WORKDIR /app
COPY run.sh /run.sh
COPY suitch.py /app/suitch.py

RUN chmod +x /run.sh

CMD ["/run.sh"]
