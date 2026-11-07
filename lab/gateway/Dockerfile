# Gateway TLS del modo endurecido.
# Genera un certificado autofirmado de laboratorio: en producción se usa ACME/CA interna.
FROM nginx:1.27-alpine

RUN apk add --no-cache openssl \
 && mkdir -p /etc/nginx/tls \
 && openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
      -keyout /etc/nginx/tls/lab.key -out /etc/nginx/tls/lab.crt \
      -subj "/C=CO/ST=Cordoba/L=Monteria/O=TCC Seguridad 2026-2/CN=127.0.0.1" \
      -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" \
 && chmod 600 /etc/nginx/tls/lab.key

COPY nginx.conf /etc/nginx/conf.d/default.conf
