"""Gera conteudo.enc.json: carta, casos, gatos e fotos, tudo criptografado.

Criptografia: AES-256-GCM com chave derivada (PBKDF2-SHA256) da senha.
Senha padrao: data de inicio do namoro, so digitos (31102020).

Arquivos locais (nao vao para o GitHub):
    carta.txt   texto da carta, exatamente como escrito
    casos.json  casos da linha do tempo (fotos por arquivo)
    gatos.json  gatos com nome, pessoa e foto

Fotos sao lidas de FOTOS_DIR, redimensionadas e salvas sem metadados (EXIF).

Uso:
    python gerar_conteudo.py              # senha 31102020
    python gerar_conteudo.py 31102020     # senha explicita
"""
import base64
import io
import json
import os
import sys

from PIL import Image
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

HERE = os.path.dirname(os.path.abspath(__file__))
FOTOS_DIR = r"C:\Users\LUCAS\OneDrive\Área de Trabalho\6y"
ITERATIONS = 200_000
SENHA_PADRAO = "31102020"
LADO_MAX = 1280
QUALIDADE = 82


def derivar_chave(senha: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS)
    return kdf.derive(senha.encode("utf-8"))


def ler_json(nome: str):
    with open(os.path.join(HERE, nome), encoding="utf-8") as f:
        return json.load(f)


def foto_para_data_uri(caminho: str) -> str:
    img = Image.open(caminho).convert("RGB")
    img.thumbnail((LADO_MAX, LADO_MAX))
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=QUALIDADE, optimize=True)  # sem EXIF
    return "data:image/jpeg;base64," + base64.b64encode(buf.getvalue()).decode()


def main() -> None:
    senha = "".join(ch for ch in (sys.argv[1] if len(sys.argv) > 1 else SENHA_PADRAO) if ch.isdigit())
    if len(senha) != 8:
        sys.exit("A senha precisa ter 8 digitos (DDMMAAAA).")

    with open(os.path.join(HERE, "carta.txt"), encoding="utf-8") as f:
        carta = f.read().strip()
    casos = ler_json("casos.json")
    gatos = ler_json("gatos.json")

    # Fotos dos casos: so as que existem na pasta (webp de baixa resolucao fica de fora).
    fotos_casos = []
    for c in casos:
        for arq in c["fotos"]:
            caminho = os.path.join(FOTOS_DIR, arq)
            if arq.lower().endswith(".webp") or not os.path.exists(caminho):
                print("ignorada:", arq)
                continue
            fotos_casos.append({"caso": c["caso"], "ano": c["ano"], "arquivo": arq, "src": foto_para_data_uri(caminho)})

    # Fotos dos gatos (uma por entrada, com a mesma imagem reaproveitada se repetida).
    cache = {}
    for g in gatos:
        arq = g.get("foto")
        if arq:
            if arq not in cache:
                cache[arq] = foto_para_data_uri(os.path.join(FOTOS_DIR, arq))
            g["src"] = cache[arq]

    payload = json.dumps(
        {"carta": carta, "casos": casos, "fotos": fotos_casos, "gatos": gatos},
        ensure_ascii=False,
    ).encode("utf-8")

    salt = os.urandom(16)
    iv = os.urandom(12)
    chave = derivar_chave(senha, salt)
    ct = AESGCM(chave).encrypt(iv, payload, None)

    saida = {
        "v": 2,
        "iter": ITERATIONS,
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ct": base64.b64encode(ct).decode(),
    }
    with open(os.path.join(HERE, "conteudo.enc.json"), "w", encoding="utf-8") as f:
        json.dump(saida, f)
    print(f"conteudo.enc.json gerado: {len(fotos_casos)} fotos de casos, {len(cache)} fotos de gatos, {os.path.getsize(os.path.join(HERE, 'conteudo.enc.json')) // 1024} KB")


if __name__ == "__main__":
    main()
