FROM python:3.7-alpine
MAINTAINER Aleksei Zhukov <drdaeman@drdaeman.pp.ru>

ENV DATA_DIR=/srv
RUN mkdir -p /opt/firesync "${DATA_DIR}"
WORKDIR /opt/firesync

COPY requirements.txt /opt/firesync
RUN apk add --no-cache --virtual .build-deps python3-dev gcc musl-dev libffi-dev openssl-dev \
 && pip install -r requirements.txt && pip install gunicorn \
 && apk del .build-deps

# Hack: patch PyBrowserID (dirty, sorry about this)
COPY cio.py /usr/local/lib/python3.7/site-packages/browserid/crypto/cio.py
RUN sed -ie 's/browserid\.crypto\.m2/browserid.crypto.cio/' /usr/local/lib/python3.7/site-packages/browserid/crypto/__init__.py

COPY . /opt/firesync
RUN python manage.py collectstatic --noinput

VOLUME /srv
EXPOSE 8000

CMD ["gunicorn", "-b", "0.0.0.0:8000", "firesync.wsgi"]
