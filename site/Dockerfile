FROM python:3.12-slim

# bash y curl para ejecutar los ataques desde el panel; psql para el ataque de
# hashes (lee la base directamente, sin depender del CLI de Docker).
RUN apt-get update \
 && apt-get install -y --no-install-recommends bash curl ca-certificates postgresql-client \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir pyyaml==6.0.2

WORKDIR /site
COPY build_data.py /site/build_data.py
COPY server.py /site/server.py
COPY static /site/static

# Usuario sin privilegios: el contenedor no corre como root.
RUN useradd --system --uid 10001 --home-dir /site --shell /usr/sbin/nologin panel \
 && mkdir -p /site/static/data \
 && chown -R panel:panel /site/static

USER panel

EXPOSE 8000

# Solo lectura sobre el repositorio: el panel lee evidencias, nunca las escribe.
ENTRYPOINT ["python", "/site/server.py"]
