import hashlib
import hmac
import logging
import os
import re
import unicodedata

import requests
from flask import Flask, request

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("fbbot")

GRAPH_VERSION = "v21.0"

VERIFY_TOKEN = os.environ.get("FB_VERIFY_TOKEN", "")
APP_SECRET = os.environ.get("FB_APP_SECRET", "")
PAGE_ACCESS_TOKEN = os.environ.get("FB_PAGE_ACCESS_TOKEN", "")
PAGE_ID = os.environ.get("FB_PAGE_ID", "")
IMAGEN_RESPUESTA_URL = os.environ.get("IMAGEN_RESPUESTA_URL", "")

PALABRAS_CLAVE = [
    "cita", "citas",
    "pasaporte", "pasaportes",
    "consulado", "consulados",
    "peruano", "peruana", "peruanos", "peruanas",
    "dni",
    "salvoconducto", "salvoconductos",
    "carta poder",
]

RESPUESTA_GENERICA = (
    "¡Hola! Para citas y trámites en el Consulado General del Perú en Madrid "
    "(pasaportes, DNI, salvoconductos, carta poder, etc.) debes reservar tu cita "
    "a través del sistema oficial de citas del Ministerio de Relaciones Exteriores: "
    "https://citas.rree.gob.pe/. Ahí eliges el consulado, el trámite y la fecha disponible."
)


def normalizar(texto):
    texto = unicodedata.normalize("NFD", texto.lower())
    return "".join(c for c in texto if unicodedata.category(c) != "Mn")


_PATRON = re.compile(
    r"\b(?:" + "|".join(re.escape(normalizar(p)) for p in PALABRAS_CLAVE) + r")\b"
)


def contiene_palabra_clave(texto):
    return bool(_PATRON.search(normalizar(texto or "")))


def firma_valida(cuerpo, cabecera):
    if not APP_SECRET:
        log.warning("FB_APP_SECRET no configurado: no se valida la firma")
        return True
    if not cabecera or not cabecera.startswith("sha256="):
        return False
    esperado = hmac.new(APP_SECRET.encode(), cuerpo, hashlib.sha256).hexdigest()
    return hmac.compare_digest(esperado, cabecera.split("=", 1)[1])


def responder_comentario(comment_id):
    url = f"https://graph.facebook.com/{GRAPH_VERSION}/{comment_id}/comments"
    data = {"message": RESPUESTA_GENERICA, "access_token": PAGE_ACCESS_TOKEN}
    if IMAGEN_RESPUESTA_URL:
        data["attachment_url"] = IMAGEN_RESPUESTA_URL
    r = requests.post(url, data=data, timeout=15)
    return r.json()


@app.get("/")
def salud():
    return "ok", 200


@app.get("/privacidad")
def privacidad():
    return (
        "<html><head><meta charset='utf-8'><title>Política de privacidad</title></head><body>"
        "<h1>Política de privacidad - Machupichu Bot</h1>"
        "<p>Este bot responde automáticamente a comentarios públicos de la Página de Facebook "
        "Machupichu cuando contienen palabras clave sobre trámites consulares.</p>"
        "<p>No almacenamos datos personales ni los comentarios: se procesan en el momento "
        "y no se guardan ni se comparten con terceros.</p>"
        "<p>Para consultas o eliminación de datos escribe a la Página de Facebook Machupichu.</p>"
        "</body></html>"
)


@app.get("/webhook")
def verificar():
    if (
        request.args.get("hub.mode") == "subscribe"
        and VERIFY_TOKEN
        and request.args.get("hub.verify_token") == VERIFY_TOKEN
    ):
        return request.args.get("hub.challenge", ""), 200
    return "Token de verificación inválido", 403


@app.post("/webhook")
def recibir():
    if not firma_valida(request.get_data(), request.headers.get("X-Hub-Signature-256", "")):
        return "Firma inválida", 403

    data = request.get_json(silent=True) or {}
    try:
        for entry in data.get("entry", []):
            for change in entry.get("changes", []):
                v = change.get("value", {})
                if change.get("field") != "feed" or v.get("item") != "comment" or v.get("verb") != "add":
                    continue
                comment_id = v.get("comment_id")
                autor = (v.get("from") or {}).get("id")
                if PAGE_ID and autor == PAGE_ID:
                    continue
                if comment_id and contiene_palabra_clave(v.get("message", "")):
                    res = responder_comentario(comment_id)
                    log.info("Respuesta a %s: %s", comment_id, res)
    except Exception:
        log.exception("Error procesando webhook")
    return "OK", 200


if __name__ == "__main__":
    app.run(port=int(os.environ.get("PORT", 5000)))
