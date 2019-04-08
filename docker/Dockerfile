FROM python:3.6
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl screen vim wget git \
      && apt-get clean \
      && rm -rf /var/lib/apt/lists/* \
      && python3 -m pip install requests flask pyopenssl uwsgi \
      && git clone https://github.com/ktmrmshk/ssl_flash.git

ENV PYTHONPATH /ssl_flash

CMD ["uwsgi", "--http", ":5000", "--wsgi-file", "/ssl_flash/sslflash_web.py", "--callable", "app"]

EXPOSE 5000
