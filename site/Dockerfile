FROM python:3.12-alpine

RUN pip install --no-cache-dir pyyaml==6.0.2

WORKDIR /site
COPY build_data.py /site/build_data.py
COPY static /site/static

EXPOSE 8000

# Regenera los datos desde el repositorio y sirve el panel.
CMD ["sh", "-c", "python /site/build_data.py && exec python -m http.server 8000 --bind 0.0.0.0 --directory /site/static"]
