"""F7.4.6 (auditoria 106): segredo é redigido NA ESCRITA, não só numa limpeza posterior.

Prova, nos dois pontos de escrita do gateway:

1. ``sessions.json`` + tabela ``gateway_routing`` do ``state.db`` — o índice de rotas gravado por
   ``SessionStore`` (é onde ``active_turn_token`` ia em claro a cada turno);
2. tabela ``messages`` do ``state.db`` — conteúdo, ``tool_calls``, ``api_content`` e reasoning de
   toda mensagem que entra (append, batch, replace...).

E prova o inverso: mensagem/entrada sem segredo sai BYTE A BYTE igual ao que entraria antes desta
mudança (a redação é identidade no tráfego normal — nada de "redigir por precaução" o que não é
segredo).

Os valores falsos são montados por concatenação de propósito: nada aqui carrega chave real.
"""

import json

import pytest

import hermes_secret_redaction as redacao
from gateway.config import GatewayConfig, Platform
from gateway.session import SessionSource, SessionStore
from hermes_state import SessionDB

MARCA = "[REDACTED]"

# Mesma família dos achados da 2ª passada do R-16 (incl. as DUAS credenciais em URL na MESMA célula,
# caso que quebrou a 1ª passada do scrub).
SEGREDOS = {
    "sk": "sk-" + "A1b2C3d4" * 4,
    "gh": "ghp_" + "b2C3d4E5" * 3,
    "url1": "https://x-access-token:" + "P4ssWord1" + "@github.com/Stronk94/casa-servicos.git",
    "url2": "https://x-access-token:" + "P4ssWord2" + "@github.com/Stronk94/casa-docs.git",
}
CHAVE_ATRIBUIDA = "OPENCODE_GO_API_KEY_3=" + "sk-" + "Q7w8E9r0" * 4


# --------------------------------------------------------------------------------------
# 1. A redação em si (fonte única = regex do scrub_state_db.py)
# --------------------------------------------------------------------------------------
def test_duas_credenciais_em_url_na_mesma_celula():
    """Regressão do R-16: as duas URLs na mesma célula, com o resto do texto preservado."""
    texto = (
        "clone 1: " + SEGREDOS["url1"] + "\n"
        "clone 2: " + SEGREDOS["url2"] + "\n"
        "fim"
    )
    limpo = redacao.redigir_texto(texto)
    assert limpo.count(MARCA) == 2
    for segredo in (SEGREDOS["url1"], SEGREDOS["url2"]):
        assert segredo not in limpo
    assert "https://x-access-token:" in limpo
    assert "@github.com/Stronk94/casa-servicos.git" in limpo
    assert "@github.com/Stronk94/casa-docs.git" in limpo
    assert limpo.startswith("clone 1: ") and limpo.endswith("\nfim")


@pytest.mark.parametrize("nome", ["sk", "gh"])
def test_padroes_de_chave(nome):
    texto = "valor: " + SEGREDOS[nome] + " (fim)"
    limpo = redacao.redigir_texto(texto)
    assert SEGREDOS[nome] not in limpo
    assert limpo == "valor: " + MARCA + " (fim)"


def test_bearer_preserva_o_esquema():
    valor = "Z9y8X7w6" * 4
    limpo = redacao.redigir_texto("Authorization: Bearer " + valor + " (fim)")
    assert valor not in limpo
    assert limpo == "Authorization: Bearer " + MARCA + " (fim)"


def test_atribuicao_de_chave_preserva_o_nome():
    limpo = redacao.redigir_texto("antes " + CHAVE_ATRIBUIDA + " depois")
    assert limpo == "antes OPENCODE_GO_API_KEY_3=" + MARCA + " depois"


def test_token_de_bot_do_telegram_sem_nome_de_chave():
    """O porteiro daqui é superconjunto do scrub: token de bot solto também é redigido."""
    token = "123456789:" + "A" * 35  # 8-12 dígitos, ':', 35 chars (formato do bot do Telegram)
    limpo = redacao.redigir_texto("chave do bot " + token)
    assert token not in limpo
    assert limpo == "chave do bot " + MARCA


def test_idempotente_na_marca():
    ja = "OPENCODE_GO_API_KEY_3=" + MARCA
    assert redacao.redigir_texto(ja) == ja
    assert redacao.redigir_texto(MARCA) == MARCA


@pytest.mark.parametrize("texto", [
    "",
    "olá, tudo bem?",
    "senha do wifi mudou",          # casa o porteiro, não casa padrão nenhum
    "veja https://github.com/Stronk94/casa-servicos",  # URL sem credencial
    "custo: R$ 12,00 às 18:30",
])
def test_texto_limpo_volta_identico(texto):
    assert redacao.redigir_texto(texto) is texto or redacao.redigir_texto(texto) == texto


def test_redigir_mensagem_e_identidade_em_mensagem_limpa():
    msg = {
        "role": "assistant",
        "content": "resposta normal",
        "tool_calls": [{"id": "call_1", "type": "function",
                        "function": {"name": "terminal", "arguments": json.dumps({"command": "ls -la"})}}],
        "reasoning_content": "pensando no problema",
        "tool_name": "terminal",
        "api_content": "resposta normal",
    }
    assert redacao.redigir_mensagem(msg) == msg


# --------------------------------------------------------------------------------------
# 2. sessions.json (espelho) e gateway_routing (state.db): active_turn_token redigido
# --------------------------------------------------------------------------------------
def _source() -> SessionSource:
    return SessionSource(
        platform=Platform.DISCORD,
        chat_id="chat-1",
        user_id="user-1",
        chat_type="channel",
        chat_name="canal de teste",
        thread_id="thread-1",
    )


def _store_json(tmp_path) -> SessionStore:
    store = SessionStore(sessions_dir=tmp_path, config=GatewayConfig())
    store._db = None  # fallback determinístico: o espelho sessions.json é a única escrita
    return store


def _store_db(tmp_path) -> SessionStore:
    store = SessionStore(sessions_dir=tmp_path / "sessions", config=GatewayConfig())
    if store._db is not None:
        store._db.close()
    store._db = SessionDB(db_path=tmp_path / "state.db")
    return store


def test_sessions_json_grava_token_redigido_e_resto_igual(tmp_path):
    store = _store_json(tmp_path)
    entry = store.get_or_create_session(_source())
    token = store.mark_turn_active(entry.session_key)
    assert token

    arquivo = tmp_path / "sessions.json"
    texto = arquivo.read_text(encoding="utf-8")
    assert token not in texto, "o token do turno não pode nascer em claro no sessions.json"

    gravado = json.loads(texto)[entry.session_key]
    assert gravado["active_turn_token"] == MARCA
    # o resto é EXATAMENTE o que a entrada publica em memória
    esperado = entry.to_dict()
    assert esperado["active_turn_token"] == token  # memória segue com o token real
    esperado["active_turn_token"] = MARCA
    assert gravado == esperado


def test_gateway_routing_do_state_db_grava_token_redigido(tmp_path):
    store = _store_db(tmp_path)
    entry = store.get_or_create_session(_source())
    token = store.mark_turn_active(entry.session_key)
    assert token

    linhas = store._db._read_all("SELECT session_key, entry_json FROM gateway_routing")
    assert linhas
    assert all(token not in (linha["entry_json"] or "") for linha in linhas), (
        "o token do turno não pode nascer em claro na tabela gateway_routing")
    guardado = next(json.loads(linha["entry_json"]) for linha in linhas
                    if linha["session_key"] == entry.session_key)
    assert guardado["active_turn_token"] == MARCA
    esperado = entry.to_dict()
    esperado["active_turn_token"] = MARCA
    assert guardado == esperado

    # o espelho continua coerente e sem o token
    if (tmp_path / "sessions" / "sessions.json").exists():
        assert token not in (tmp_path / "sessions" / "sessions.json").read_text(encoding="utf-8")


def test_entrada_sem_segredo_nao_muda(tmp_path):
    store = _store_json(tmp_path)
    entry = store.get_or_create_session(_source())
    store._save_entry(entry.session_key)
    gravado = json.loads((tmp_path / "sessions.json").read_text(encoding="utf-8"))[entry.session_key]
    assert gravado == entry.to_dict()


def test_clear_turn_active_continua_funcionando(tmp_path):
    """A marca no disco não atrapalha o CAS em memória do processo vivo."""
    store = _store_db(tmp_path)
    entry = store.get_or_create_session(_source())
    token = store.mark_turn_active(entry.session_key)
    assert store.clear_turn_active(entry.session_key, token) is True
    guardado = json.loads(store._db._read_all(
        "SELECT entry_json FROM gateway_routing WHERE session_key = ?", (entry.session_key,))[0]["entry_json"])
    assert guardado["active_turn_token"] is None


# --------------------------------------------------------------------------------------
# 3. Tabela messages do state.db: conteúdo, tool_calls, api_content e reasoning
# --------------------------------------------------------------------------------------
@pytest.fixture()
def db(tmp_path):
    base = SessionDB(db_path=tmp_path / "state.db")
    base.create_session("sess-redacao", source="cli")
    yield base
    base.close()


def _linha(db, sessao="sess-redacao"):
    return db._read_all(
        "SELECT role, content, tool_calls, tool_name, api_content, reasoning_content, reasoning "
        "FROM messages WHERE session_id = ? ORDER BY id DESC LIMIT 1", (sessao,))[0]


def test_append_message_redige_o_valor_e_preserva_o_resto(db):
    conteudo = "saida do comando:\n" + CHAVE_ATRIBUIDA + "\nfim da saida"
    db.append_message("sess-redacao", "tool", content=conteudo, tool_name="terminal",
                      tool_call_id="call_1")
    linha = _linha(db)
    assert linha["content"] == "saida do comando:\nOPENCODE_GO_API_KEY_3=" + MARCA + "\nfim da saida"
    assert CHAVE_ATRIBUIDA not in linha["content"]
    assert linha["tool_name"] == "terminal"
    assert linha["role"] == "tool"


def test_argumentos_de_tool_call_redigidos(db):
    argumentos = json.dumps({"command": "export OPENCODE_GO_API_KEY_3=" + SEGREDOS["sk"], "timeout": 30})
    chamadas = [{"id": "call_1", "type": "function",
                 "function": {"name": "terminal", "arguments": argumentos}}]
    db.append_message("sess-redacao", "assistant", content="vou rodar", tool_calls=chamadas)

    linha = _linha(db)
    assert SEGREDOS["sk"] not in linha["tool_calls"]
    guardadas = json.loads(linha["tool_calls"])
    assert guardadas[0]["function"]["name"] == "terminal"
    assert guardadas[0]["id"] == "call_1"
    argumentos_guardados = json.loads(guardadas[0]["function"]["arguments"])
    assert argumentos_guardados == {"command": "export OPENCODE_GO_API_KEY_3=" + MARCA, "timeout": 30}
    # o dict vivo do chamador não foi mutado
    assert chamadas[0]["function"]["arguments"] == argumentos


def test_api_content_e_reasoning_redigidos(db):
    db.append_message(
        "sess-redacao", "assistant",
        content="resposta",
        api_content="resposta com " + SEGREDOS["sk"],
        reasoning_content="pensei em " + SEGREDOS["gh"],
        reasoning="vou usar " + SEGREDOS["sk"],
    )
    linha = _linha(db)
    assert linha["api_content"] == "resposta com " + MARCA
    assert linha["reasoning_content"] == "pensei em " + MARCA
    assert linha["reasoning"] == "vou usar " + MARCA


def test_mensagem_limpa_grava_byte_a_byte_igual(db):
    db.append_message("sess-redacao", "user", content="pergunta simples, sem chave")
    linha = _linha(db)
    assert linha["content"] == "pergunta simples, sem chave"
    assert linha["tool_calls"] is None
    assert linha["api_content"] is None
    assert linha["reasoning_content"] is None

    db.append_message("sess-redacao", "assistant", content="resposta",
                      tool_calls=[{"id": "c1", "type": "function",
                                   "function": {"name": "read_file", "arguments": '{"path": "/tmp/x"}'}}])
    linha = _linha(db)
    assert json.loads(linha["tool_calls"]) == [{"id": "c1", "type": "function",
                                               "function": {"name": "read_file", "arguments": '{"path": "/tmp/x"}'}}]


def test_batch_tambem_redige(db):
    db.append_messages_batch("sess-redacao", [
        {"role": "user", "content": "chave: " + SEGREDOS["gh"]},
        {"role": "assistant", "content": "ok"},
    ])
    linhas = db._read_all("SELECT content FROM messages WHERE session_id = ? ORDER BY id", ("sess-redacao",))
    assert linhas[0]["content"] == "chave: " + MARCA
    assert linhas[1]["content"] == "ok"


# --------------------------------------------------------------------------------------
# 4. Blob de resultado do turno em state_meta (gateway.admission.result.v1.*)
#    — os outros achados da 2ª passada do R-16 nasceram aqui.
# --------------------------------------------------------------------------------------
def test_blob_de_resultado_do_turno_redigido():
    from hermes_state_terminal import encode_result, load_result

    resultado = {
        "result": {
            "messages": [
                {"role": "user", "content": "rode o comando"},
                {"role": "tool", "content": "saida: " + CHAVE_ATRIBUIDA},
                {"role": "assistant", "content": "pronto"},
            ],
            "final_response": "pronto",
        },
        "usage": {"output_tokens": 12},
    }
    guardado = json.dumps(encode_result(resultado))
    assert SEGREDOS["sk"] not in guardado
    assert "OPENCODE_GO_API_KEY_3=" + MARCA in guardado
    # a comparação com final_response continua válida DEPOIS da redação: o stash segue funcionando
    assert "\"pronto\"" in guardado and '"usage": {"output_tokens": 12}' in guardado
    decodificado = load_result(guardado)
    assert decodificado["result"]["messages"][1]["content"] == "saida: OPENCODE_GO_API_KEY_3=" + MARCA


def test_blob_de_resultado_com_segredo_na_resposta_final_ainda_usa_stash():
    from hermes_state_terminal import encode_result

    resposta = "sua chave e " + SEGREDOS["sk"]
    guardado = encode_result({
        "result": {
            "messages": [{"role": "assistant", "content": resposta}],
            "final_response": resposta,
        },
    })
    assert SEGREDOS["sk"] not in json.dumps(guardado)
    # o stash do reply (content None + _stored.reply_ref) continua acontecendo
    assert guardado["result"]["messages"][0]["content"] is None
    assert guardado["_stored"] == {"v": 1, "reply_ref": 0}
    assert guardado["result"]["final_response"] == "sua chave e " + MARCA
