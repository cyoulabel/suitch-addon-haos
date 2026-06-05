FROM python:3.12-alpine

WORKDIR /app
COPY run.sh /run.sh
COPY suitch.py /app/suitch.py

RUN chmod +x /run.sh

CMD ["/run.sh"]
