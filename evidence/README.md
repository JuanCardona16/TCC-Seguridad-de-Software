# Evidencias del laboratorio

Todo lo que hay acá se **regenera** ejecutando la suite; nada está escrito a mano.

| Ruta | Contenido | Cómo se genera |
|---|---|---|
| `results.json` | Resumen de la matriz antes/después: un registro por ataque y por modo, con veredicto PASS/FAIL/SKIP | `bash attacks/run-all.sh` |
| `results.jsonl` | Un objeto JSON por línea, insumo de `results.json` | `bash attacks/run-all.sh` |
| `http/vulnerable/<ataque>.log` | Salida literal de cada ataque contra el modo vulnerable | `bash attacks/run-all.sh` |
| `http/hardened/<ataque>.log` | Salida literal de cada ataque contra el modo endurecido | `bash attacks/run-all.sh` |
| `http/<modo>/*.html` | Respuestas HTTP crudas usadas como prueba | misma ejecución |
| `network/09-http.pcap` | Captura donde se leen las credenciales en claro | `attacks/09-tls-plaintext.sh` |
| `network/09-tls.pcap` | Captura del mismo login sobre TLS (solo cifrado) | `attacks/09-tls-plaintext.sh` |
| `.cache/` | Cookies de sesión de las pruebas (desechables) | misma ejecución |

## Cómo leer el resultado

```bash
jq -r '.attacks[] | [.id, .mode, .verdict, .detail] | @tsv' evidence/results.json | column -t -s$'\t'
jq '.summary' evidence/results.json
```

* `PASS` en modo `vulnerable` significa que **el ataque funcionó** (el defecto existe).
* `PASS` en modo `hardened` significa que **el ataque fue bloqueado** (la mitigación funciona).
* `FAIL` es un hallazgo real del informe: la expectativa no se cumplió y hay que corregir el
  código o la prueba.
* `SKIP` indica que la prueba no pudo ejecutarse (por ejemplo, falta el perfil `tools`).

## Reglas de higiene

1. Las capturas se toman **dentro** de la red del laboratorio. No se captura tráfico del host.
2. Los datos son simulados. Nunca se usan credenciales, documentos ni datos de personas reales.
3. Los `.pcap` no se versionan (pesan y se regeneran): ver `.gitignore`.
