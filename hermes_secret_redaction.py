"""Redação de segredo NA ESCRITA — item F7.4.6 (auditoria 106, depende do 105).

Objetivo: segredo nenhum nasce em disco. Este módulo é aplicado nos pontos de escrita do gateway
Hermes (``redigir_entrada_sessao`` / ``redigir_mensagem`` / ``redigir_valor``):

  * ``gateway/session_persistence.py::_persist_routing_data`` (índice inteiro),
    ``_save_sessions_json`` (espelho ``sessions.json``) e ``_save_entry`` (UPSERT por turno) — as
    três escritas do índice de rotas, que persiste em ``sessions.json`` e na tabela
    ``gateway_routing`` do ``state.db``. É ali que ``active_turn_token`` ia em claro a cada turno;
  * ``gateway/session_api.py::bind_api_steps`` — a rota que o caminho de API grava direto em
    ``gateway_routing``;
  * ``hermes_state_messages.py::SessionDB._message_row_params`` — toda mensagem que entra na tabela
    ``messages`` (append, batch, replace, compact, import passam por aqui), inclusive os argumentos
    das ``tool_calls`` e o ``api_content``;
  * ``hermes_state_terminal.py::encode_result`` — o blob do turno inteiro que vai para
    ``state_meta['gateway.admission.result.v1.*']`` (é onde a 2ª passada do R-16 achou 3 das 5
    ocorrências: o resultado da tool atravessa o blob).

Fonte única dos padrões: ``casa-servicos/.hermes/scripts/scrub_state_db.py`` (R-16), na versão da
2ª passada — branch ``fix/r16-scrub-regex-2a``, commit ``0e4b220`` ("regex do scrub aceita duas URLs
x-access-token na mesma celula"), que ainda NÃO está na ``main`` do casa-servicos (a main tem o
regex anterior, que atravessa a marca e come o host). O bloco ``PADROES``/``RX_PEM`` abaixo é cópia
LITERAL daquele commit — se mudar o scrub, mude aqui junto (mesmo regex, mesmo comportamento); o
teste ``tests/test_secret_redaction_on_write.py`` cobre justamente o caso das duas credenciais em
URL na MESMA célula, com o host preservado. O porteiro ``RX_PREFILTRO`` é só otimização (evita rodar
12 regex por mensagem) e aqui é um SUPERCONJUNTO do scrub: leva ``\\d{8,12}:`` porque um token de bot
do Telegram sem nome de chave ao lado escapava do porteiro do scrub.

Contrato: a redação devolve o texto com a marca ``[REDACTED]`` no lugar do valor e NUNCA devolve,
loga ou conta o valor. É idempotente — a própria marca não é segredo (mesma marca do scrub, então
uma célula já scrubbed não volta a ser tocada).
"""

from __future__ import annotations

import re
from typing import Any, Iterable

# Mesma marca do scrub_state_db.py: é o que torna a redação idempotente e reconhecível na auditoria.
MARCA = "[REDACTED]"

PADROES: tuple[tuple[str, re.Pattern[str], int], ...] = (
    ("openai/anthropic-sk", re.compile(r"\b(sk-(?:proj-|ant-)?[A-Za-z0-9_\-]{16,})"), 1),
    ("github-token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,})"), 1),
    ("github-pat", re.compile(r"\b(github_pat_[A-Za-z0-9_]{20,})"), 1),
    ("slack-token", re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})"), 1),
    ("aws-access-key", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), 1),
    ("google-api-key", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b"), 1),
    ("jwt", re.compile(r"\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,})\b"), 1),
    ("telegram-bot-token", re.compile(r"(?<!\d)(\d{8,12}:[A-Za-z0-9_-]{35})(?![\w-])"), 1),
    ("bws-token", re.compile(r"\b(0\.[0-9a-fA-F-]{36}\.[0-9a-fA-F-]{36}\.[A-Za-z0-9+/=]{16,})"), 1),
    ("bearer", re.compile(r"(?i)\b(Bearer\s+)([^\s\"',;]{8,})"), 2),
    # `esquema://usuário:senha@host`. Três travas que vieram do R-16 (2ª passada):
    #  - o VALOR não aceita aspas, colchete, `<`, `>` nem `\` (chave não tem esses caracteres);
    #  - o `@` só conta se vier um HOST logo depois (antes, um `@` de `git@host` lá na frente
    #    servia de âncora e o casamento atravessava a marca já trocada e a prosa do meio);
    #  - o usuário também não aceita `[`/`]`, então `x-access-token:[REDACTED]@host` não recasa.
    # Sem isso, a célula com duas URLs `x-access-token:` (rowid 168969/168986 do `default`)
    # deixava uma "ocorrência" que era falso-positivo a cada passada.
    ("credencial-em-url", re.compile(
        r"(?i)\b([a-z][a-z0-9+.\-]*://[^\s:@/\"'`<>\\\[\]]+:)"
        r"([^\s@/\"'`<>\\\[\]]{3,})"
        r"(@[A-Za-z0-9][A-Za-z0-9.\-]*)"), 2),
    # NOME_DA_CHAVE=valor / "token": "valor" / senha: valor  (o nome precisa ter cara de segredo).
    # O valor não aceita `[`/`]` — é o que impede `x-access-token:[REDACTED]@host:` (marca já
    # posta) de virar ocorrência nova a cada passada.
    ("atribuicao-de-segredo", re.compile(
        r"(?i)\b([A-Za-z0-9_.\-]*"
        r"(?:API[_-]?KEY|ACCESS[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|SENHA|PRIVATE[_-]?KEY)"
        r"[A-Za-z0-9_.\-]*\s*[:=]\s*[\"']?)[\"']?"
        r"([^\s\"',;\[\]]{8,})"), 2),
)

# Bloco PEM inteiro (multi-linha) — tratado antes, no texto todo.
RX_PEM = re.compile(r"-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----.*?(?:-----END \1-----|\Z)", re.S)


# Porteiro barato (só otimização, nunca decide sozinho o que é segredo): se o texto não tem nenhum
# destes pedaços, nenhum padrão acima pode casar — exceto o token de bot do Telegram sem nome de
# chave ao lado, por isso ``\d{8,12}:`` entra aqui (o scrub não tem essa alternativa; ver docstring).
RX_PREFILTRO = re.compile(
    r"(?i)sk-|gh[pousr]_|github_pat_|xox|akia|asia|aiza|eyj|bearer|://|private key|"
    r"token|secret|senha|password|passwd|key\s*[:=]|\d{8,12}:",
)


# --------------------------------------------------------------------------------------
# Redação (o valor não sai daqui; só o texto com a marca)
# --------------------------------------------------------------------------------------
def tem_cara_de_segredo(texto: Any) -> bool:
    """True when *texto* deserves the full pattern run (cheap gate, same one used by ``redigir``)."""
    return isinstance(texto, str) and bool(texto) and RX_PREFILTRO.search(texto) is not None


def _troca(m: re.Match[str], grupo: int) -> str:
    """Replace only the value group, keeping everything the pattern matched around it."""
    if m.group(grupo) == MARCA:  # idempotência: a marca não é segredo
        return m.group(0)
    ini, fim = m.span(grupo)
    base = m.start(0)
    return m.group(0)[: ini - base] + MARCA + m.group(0)[fim - base:]


def redigir_texto(texto: Any) -> Any:
    """*texto* with every secret-shaped value replaced by ``MARCA``; non-strings pass through.

    Byte-identical to the input when there is nothing secret-shaped inside, which is what keeps
    ``sessions.json``/``messages`` unchanged for ordinary traffic.
    """
    if not isinstance(texto, str) or not texto:
        return texto
    if RX_PREFILTRO.search(texto) is None:
        return texto
    atual = texto
    if "PRIVATE KEY" in atual:
        atual = RX_PEM.sub(MARCA, atual)
    for _nome, rx, grupo in PADROES:
        if rx.search(atual) is not None:
            atual = rx.sub(lambda m, _g=grupo: _troca(m, _g), atual)
    return atual


def redigir_valor(valor: Any, *, chaves_intocadas: Iterable[str] = ()) -> Any:
    """Recursively redact strings inside JSON-able structures (dict/list/tuple), preserving shape.

    Keys in *chaves_intocadas* are left alone entirely: ids and other identifiers must round-trip
    (a redacted ``session_id`` would break routing, a redacted ``chat_id`` would break delivery).
    """
    if isinstance(valor, str):
        return redigir_texto(valor)
    if isinstance(valor, dict):
        intocadas = chaves_intocadas
        return {k: (v if k in intocadas else redigir_valor(v)) for k, v in valor.items()}
    if isinstance(valor, list):
        return [redigir_valor(v) for v in valor]
    if isinstance(valor, tuple):
        return tuple(redigir_valor(v) for v in valor)
    return valor


# Campos de texto livre do índice de rotas. Ids (``session_key``/``session_id``/``chat_id``/
# ``user_id``/``thread_id``/``created_at``...) NÃO entram: redigir identificador quebraria roteamento
# e a comparação de rotas aposentadas.
CAMPOS_TEXTO_DA_ENTRADA = ("display_name",)
CAMPOS_TEXTO_DA_ORIGEM = ("chat_name", "chat_topic", "user_name", "auto_thread_initial_name")
CAMPOS_LIVRES_DO_MODELO = ("model", "provider")


def redigir_entrada_sessao(entrada: dict[str, Any]) -> dict[str, Any]:
    """Copy of a routing-index entry (:meth:`SessionEntry.to_dict`) with secrets redacted.

    ``active_turn_token`` becomes ``MARCA`` whenever it was set: the value is a per-turn capability
    token and no reader needs it back after a restart — the marker itself (plus
    ``active_turn_started_at``) is what the unclean-start recovery looks at, and clearing uses the
    marker that was loaded, so the round-trip stays self-consistent.
    """
    limpa = dict(entrada)
    if limpa.get("active_turn_token"):
        limpa["active_turn_token"] = MARCA
    for campo in CAMPOS_TEXTO_DA_ENTRADA:
        if isinstance(limpa.get(campo), str):
            limpa[campo] = redigir_texto(limpa[campo])
    for campo in ("metadata", "prompt_pin"):
        if isinstance(limpa.get(campo), (dict, list, tuple)):
            limpa[campo] = redigir_valor(limpa[campo])
    if isinstance(limpa.get("model_override"), dict):
        limpa["model_override"] = {
            k: (v if k in CAMPOS_LIVRES_DO_MODELO else redigir_valor(v))
            for k, v in limpa["model_override"].items()
        }
    origem = limpa.get("origin")
    if isinstance(origem, dict):
        origem = dict(origem)
        for campo in CAMPOS_TEXTO_DA_ORIGEM:
            if isinstance(origem.get(campo), str):
                origem[campo] = redigir_texto(origem[campo])
        limpa["origin"] = origem
    return limpa


# Colunas de texto da tabela ``messages`` que podem carregar valor de chave. ``content`` cobre a
# saída de ferramenta (onde a chave aparece), ``tool_calls`` os argumentos JSON das chamadas.
CAMPOS_DE_TEXTO_DA_MENSAGEM = (
    "content", "tool_calls", "tool_name", "api_content",
    "reasoning", "reasoning_content", "reasoning_details",
    "codex_reasoning_items", "codex_message_items", "display_metadata",
)


def redigir_mensagem(msg: dict[str, Any]) -> dict[str, Any]:
    """Shallow copy of a message dict with the persisted text fields redacted.

    The caller's live dict is never mutated: the agent keeps the real value in memory for the turn
    it is running; only what goes to disk is redacted.
    """
    limpa = dict(msg)
    for campo in CAMPOS_DE_TEXTO_DA_MENSAGEM:
        valor = limpa.get(campo)
        if isinstance(valor, str):
            limpa[campo] = redigir_texto(valor)
        elif isinstance(valor, (dict, list, tuple)):
            limpa[campo] = redigir_valor(valor)
    return limpa
