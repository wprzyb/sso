FROM alpine:3.11.3@sha256:ddba4d27a7ffc3f86dd6c2f92041af252a1f23a8e742c90e6e1297bfa1bc0c45
EXPOSE 5000
WORKDIR /usr/src/app

RUN apk add --no-cache \
        uwsgi-python3 \
        python3 \
        libpq git

# psycopg2 needs some extra build tools and headers. Install them and build in a
# single step in order not to pollute Docker layers
RUN apk add --no-cache --virtual .build-deps gcc python3-dev musl-dev postgresql-dev openldap-dev cyrus-sasl-dev libffi-dev && \
    pip3 install --no-cache-dir psycopg2==2.8.4 pyasn1==0.4.8 pyasn1-modules==0.2.8 python-ldap==3.2.0 cffi==1.14.0 cryptography==2.9.2 && \
    apk del --no-cache .build-deps

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

ENV FLASK_APP sso
ENV FLASK_ENV production

COPY . .
ENV prometheus_multiproc_dir /tmp
STOPSIGNAL SIGINT
USER uwsgi
CMD flask db upgrade && exec uwsgi --http-socket 0.0.0.0:5000 \
               --processes 4 \
               --plugins python3 \
               --wsgi sso.wsgi:application \
               --touch-reload sso/wsgi.py
