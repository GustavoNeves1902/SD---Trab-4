# Implementação: mapeamento teoria → código e limitações assumidas

## Onde cada conceito está implementado

| Conceito | Arquivo | O quê |
|---|---|---|
| X25519 (ECDH), AES-256-GCM, HKDF-SHA256 | [`src/crypto_primitives.py`](../src/crypto_primitives.py) | Primitivas puras, sem estado |
| Double Ratchet (DH ratchet + symmetric ratchet) | [`src/double_ratchet.py`](../src/double_ratchet.py) | Classe `DoubleRatchet`, segue o pseudocódigo oficial do Signal |
| Handshake inicial (X25519, análogo simplificado do X3DH) | [`src/client.py`](../src/client.py) (`handshake_alice` / `handshake_bob`) | Um único DH para gerar o segredo inicial |
| Transporte / servidor "zero-trust" | [`src/server.py`](../src/server.py) | Relay TCP que só vê JSON com `ciphertext` opaco |
| Verificação de corretude | [`tests/test_double_ratchet.py`](../tests/test_double_ratchet.py), [`tests/test_network_integration.py`](../tests/test_network_integration.py) | Testes automatizados (pytest) |

## Simplificações em relação ao Signal Protocol real

Estas simplificações foram feitas para manter o escopo viável em um trabalho de disciplina, mas são pontos importantes para discutir na parte teórica (trade-offs de segurança vs. praticidade):

1. **Sem X3DH completo**: o Signal real usa um *identity key* de longo prazo, um *signed prekey* (assinado com XEdDSA) e, opcionalmente, um *one-time prekey*, combinando **3 a 4 DHs** para o segredo inicial. Aqui usamos **um único DH** entre chaves efêmeras geradas na hora. Isso significa que nosso protótipo não oferece autenticação de identidade (qualquer um poderia se passar por Bob na primeira conexão) nem comunicação assíncrona real (ambos precisam estar online ao mesmo tempo para o handshake).
2. **Sem verificação de identidade fora de banda**: o Signal real permite comparar "números de segurança" (*safety numbers*) para detectar ataques *man-in-the-middle* no primeiro contato. Não implementamos isso.
3. **Sem persistência de estado**: o estado do ratchet (chaves de cadeia, chaves puladas) vive apenas em memória durante a execução do processo. Um app real persiste isso em disco de forma criptografada.
4. **Sem header encryption**: o Signal moderno também cifra os cabeçalhos das mensagens (Sesame/Header-encrypted Double Ratchet) para esconder metadados como o número da mensagem. Aqui os cabeçalhos trafegam em claro (apenas o payload é cifrado), o que é o comportamento do Double Ratchet "clássico" descrito na especificação original.
5. **`XEd25519` vs. `X25519` puro**: XEdDSA é uma técnica que permite *assinar* usando uma chave X25519 (reaproveitando o mesmo par de chaves para DH e assinatura). Como nosso handshake não inclui assinaturas de prekeys (não há autenticação), usamos X25519 puro para o acordo de chaves.
6. **Assimetria entre iniciador e respondente**: no Double Ratchet, quem "responde" (Bob, que publicou o prekey) só ganha uma *sending chain* depois de decifrar a primeira mensagem de quem "inicia" (Alice) — é essa mensagem que carrega a nova chave pública de Alice e dispara o primeiro DH ratchet do lado de Bob. Na prática isso significa que **Alice deve enviar a primeira mensagem**; se Bob tentar enviar antes disso, `chain_key_send` ainda é `None` (o cliente detecta esse caso e avisa em vez de travar). Esse comportamento é do protocolo em si, não uma limitação da nossa implementação — vale citar na parte teórica como exemplo de como o design do protocolo molda a UX de um app real (o Signal contorna isso enviando uma mensagem "vazia" de inicialização automaticamente).

## Trade-offs para discutir na parte teórica

- **AES-GCM vs. modos não autenticados (ex.: AES-CBC)**: por que AEAD é obrigatório em qualquer protocolo moderno (integridade "de graça", resistência a *padding oracle attacks*, etc.).
- **Curvas elípticas (X25519) vs. RSA**: chaves muito menores para o mesmo nível de segurança, DH mais rápido, indicado para *ephemeral keys* trocadas a cada sessão/mensagem.
- **Forward secrecy vs. custo computacional**: girar chaves a cada mensagem tem custo de CPU e de sincronização (mensagens fora de ordem, mensagens puladas) — o trade-off entre segurança e complexidade de implementação.
- **HKDF vs. usar o segredo bruto diretamente**: por que nunca se deve usar a saída de um DH diretamente como chave simétrica (não tem garantia de distribuição uniforme; HKDF resolve isso e permite derivar múltiplas chaves independentes do mesmo segredo).
