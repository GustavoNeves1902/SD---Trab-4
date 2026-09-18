# Mensageria Segura Ponto a Ponto (estilo Signal)

4º Trabalho de Sistemas Distribuídos — Opção 8: AES-256-GCM + X25519 (Double Ratchet) + HKDF (HMAC-SHA256).

Documentação completa em [docs/documentacao.md](docs/documentacao.md) (também disponível em [docs/documentacao.docx](docs/documentacao.docx)), cobrindo: explicação didática para leigos, visão geral conceitual, fundamentos matemáticos com comparação a cenários reais de mercado, e o mapeamento implementação → teoria com limitações e trade-offs.

## Estrutura

```
docs/      documentação teórica
src/       implementação (primitivas, double ratchet, servidor, cliente CLI)
tests/     testes automatizados (pytest)
```

## Setup

```powershell
python -m venv venv
./venv/Scripts/pip install -r requirements.txt
```

## Rodando os testes

```powershell
./venv/Scripts/python -m pytest tests/ -v
```

## Demo interativa (3 terminais)

**Terminal 1 — servidor (relay cego, só vê ciphertext):**
```powershell
./venv/Scripts/python src/server.py
```

**Terminal 2 — Bob:**
```powershell
./venv/Scripts/python src/client.py bob
```

**Terminal 3 — Alice:**
```powershell
./venv/Scripts/python src/client.py alice
```

Bob deve ser iniciado antes de Alice (ele publica sua chave pública inicial, que Alice usa no handshake). Depois do handshake, digite mensagens em qualquer um dos dois terminais — elas trafegam cifradas pelo servidor, que só consegue ver o envelope JSON (tipo, remetente, tamanho), nunca o texto.
