# Mensageria Segura Ponto a Ponto (estilo Signal) — Documentação

> 4º Trabalho de Sistemas Distribuídos
> Tema: Estudo comparativo de primitivas criptográficas e implementação de fluxos de segurança para a garantia da Tríade CIA (Confidencialidade, Integridade e Autenticidade)
> Opção 8: AES-GCM (256 bits) + X25519 (Double Ratchet) + HKDF (HMAC-SHA256)

## Sumário

1. [Como funciona, em termos simples](#1-como-funciona-em-termos-simples)
2. [Visão geral conceitual](#2-visão-geral-conceitual)
3. [Fundamentos matemáticos e cenários de mercado](#3-fundamentos-matemáticos-e-cenários-de-mercado)
4. [Implementação: mapeamento teoria → código e limitações](#4-implementação-mapeamento-teoria--código-e-limitações)

---

## 1. Como funciona, em termos simples

> Versão didática, para quem não tem background em criptografia.

Pense em Alice e Bob como duas pessoas trocando bilhetes através de um carteiro (o **servidor**) que não é necessariamente confiável — ele pode ler tudo que passa pelas mãos dele, então os bilhetes precisam estar dentro de uma caixa trancada que só o destinatário consegue abrir.

### O "cadeado mágico" (X25519 / Diffie-Hellman)

Cada pessoa cria um par **cadeado + chave**: guarda a chave para si (privada) e manda o cadeado aberto para o outro (pública). Isso sozinho não resolveria o problema — mas existe um truque matemático (Diffie-Hellman) que permite uma coisa incrível:

> Alice pega **sua própria chave privada** + **o cadeado público do Bob**, faz uma continha, e chega em um número secreto.
> Bob pega **sua própria chave privada** + **o cadeado público da Alice**, faz a mesma continha, e chega **no mesmo número secreto**.

Ninguém mais consegue chegar nesse número só vendo os cadeados públicos passarem pelo carteiro — é como se cada um misturasse uma tinta secreta com uma tinta pública, trocassem as misturas, e só eles conseguissem "desfazer" a mistura para chegar na mesma cor final. Esse número secreto compartilhado é a base de tudo — e nenhum dos dois nunca o enviou pela rede.

No código, isso é a função `dh()` em [crypto_primitives.py](../src/crypto_primitives.py).

### O "liquidificador de chaves" (HKDF)

Esse número secreto do passo anterior é meio "torto" — não tem a qualidade ideal para ser usado direto como senha de um cadeado real. Então ele passa por um liquidificador (HKDF) que:
- Transforma esse número em uma chave bem "lisa" e aleatória.
- Consegue tirar **várias chaves diferentes** do mesmo segredo, cada uma para um uso específico (uma para trancar mensagens, outra para continuar a corrente de chaves, etc.).

É a função `hkdf()` no mesmo arquivo, e é usada o tempo todo dentro do ratchet.

### A "caixa lacrada" (AES-256-GCM)

Com uma chave boa em mãos, a mensagem é colocada numa caixa trancada com um lacre especial:
- Sem a chave, ninguém abre a caixa (**confidencialidade**).
- Se alguém tentar violar o lacre no caminho — trocar uma única letra da mensagem — o lacre quebra visivelmente e o destinatário percebe a violação em vez de ler algo adulterado (**integridade/autenticidade**).

No teste `test_tampered_ciphertext_is_rejected`, alteramos um byte da mensagem cifrada de propósito e o sistema recusou abrir a caixa.

### A parte "estilo Signal": nunca reusar a mesma chave (Double Ratchet)

Aqui está o pulo do gato que diferencia isso de uma cifra comum. Ao invés de Alice e Bob usarem **a mesma chave para sempre**, a cada mensagem enviada:

- Gira-se uma **catraca** (ratchet — como a catraca de ônibus, só anda para frente) que transforma a chave atual numa chave nova, e descarta a antiga.
- Isso significa que se alguém roubar a chave de hoje, **as mensagens de ontem continuam seguras** — as chaves antigas já foram destruídas (isso se chama *forward secrecy*, sigilo para frente).

E, de tempos em tempos (toda vez que a conversa muda de direção — de "Alice fala" para "Bob responde"), eles fazem um **novo aperto de mão com cadeados novos** (repetem o primeiro passo com chaves frescas), misturando essa novidade na corrente de chaves. Isso significa que, mesmo que um atacante consiga espiar um pedacinho da conversa, o sistema "se cura" sozinho pouco depois (*post-compromise security*).

### O que acontece, na prática, na nossa implementação

```
1. Bob cria seu cadeado inicial e manda a parte pública   → "prekey"
2. Alice cria o dela, faz a continha mágica com o cadeado do Bob
   → chegam ambos no mesmo segredo inicial
3. Alice manda SUA parte pública para Bob                 → "identity"
4. Alice manda a 1ª mensagem, já numa caixa lacrada nova
   → Bob abre a caixa, e SÓ NESSE MOMENTO a catraca dele
     gira e ele ganha uma chave própria para responder
5. Bob responde — outra caixa, outra chave, outro lacre
6. Alice manda a 2ª mensagem — de novo, chave totalmente nova
```

Um detalhe curioso, descoberto testando o sistema de verdade: no passo 4, o Bob só ganha "permissão" para responder depois de abrir a primeira caixa da Alice. Se ele tentar escrever antes disso, o sistema ainda não tem a chave pronta — o cliente detecta esse caso e avisa em vez de travar. Isso não é uma falha da implementação: é assim que o Double Ratchet real funciona — quem "atende" a conversa precisa ouvir algo primeiro antes de poder falar (ver item 6 da [seção 4](#4-implementação-mapeamento-teoria--código-e-limitações)).

### E o carteiro (servidor) nessa história?

Ele só vê caixas lacradas passando de um lado para o outro — sabe *quem* mandou, *para quem*, e *o tamanho* da caixa, mas nunca consegue abrir nenhuma. É exatamente o que aparece no log do servidor: `"repassando 288 bytes... (conteúdo ilegível para o servidor)"`.

---

## 2. Visão geral conceitual

Esta opção consiste em recriar, em miniatura, o **Signal Protocol** — o protocolo criptográfico usado pelo Signal, WhatsApp e Google Messages (RCS) para garantir que só o remetente e o destinatário consigam ler as mensagens trocadas, mesmo que o servidor que as transporta seja comprometido (modelo "zero-trust" em relação ao servidor).

A ideia central é combinar três tipos de primitivas criptográficas, cada uma cobrindo uma parte da tríade CIA:

| Primitiva | Tipo | Papel na tríade CIA |
|---|---|---|
| AES-256-GCM | Cifra simétrica autenticada (AEAD) | Confidencialidade + Integridade + Autenticidade da mensagem |
| X25519 (dentro do Double Ratchet) | Criptografia assimétrica (Diffie-Hellman em curva elíptica) | Estabelecimento de segredo compartilhado sem nunca transmiti-lo |
| HKDF (HMAC-SHA256) | Função de derivação de chaves | Transforma segredos "brutos" em chaves de uso específico, renovadas a cada mensagem |

### AES-GCM (256 bits) — a cifra que protege cada mensagem

AES-GCM é uma cifra **simétrica** (a mesma chave cifra e decifra) no modo **Galois/Counter Mode**, que é um modo **AEAD** (Authenticated Encryption with Associated Data). Ele não apenas criptografa o texto, mas também gera uma **tag de autenticação**: se um único bit da mensagem cifrada for alterado em trânsito, a decifração falha.

Com isso, ganha-se:
- **Confidencialidade**: sem a chave, o texto cifrado é ilegível.
- **Integridade / Autenticidade**: qualquer adulteração é detectada (a tag não confere).

O problema prático: como Alice e Bob combinam essa chave simétrica sem nunca trocá-la por um canal inseguro? É aí que entra a parte assimétrica.

### X25519 e o Double Ratchet — como as chaves nascem e mudam

**X25519** é uma curva elíptica usada para **Diffie-Hellman (ECDH)**: cada parte tem um par de chaves (privada/pública) e, ao combinar "minha privada + pública do outro", ambos chegam ao **mesmo segredo**, sem que ele jamais trafegue pela rede. (No enunciado aparece "XEd25519" — é a variante que permite usar as mesmas chaves X25519 tanto para acordo de chave (ECDH) quanto para assinatura, via XEdDSA.)

O **Double Ratchet** (protocolo criado por Trevor Perrin e Moxie Marlinspike) usa X25519 repetidamente para nunca deixar a mesma chave em uso por muito tempo. Ele tem duas "catracas" (ratchets) que só giram para frente, nunca para trás:

- **DH Ratchet**: a cada troca de mensagens em um novo sentido, um novo par de chaves X25519 é gerado e um novo ECDH é feito, alimentando a derivação de chave com material novo.
- **Symmetric-key Ratchet**: dentro de uma mesma "rodada", cada mensagem individual deriva uma chave nova a partir da anterior (uma cadeia de HKDF), então nenhuma mensagem reutiliza a chave da anterior.

Isso dá duas propriedades muito valorizadas em segurança de mensageria:
- **Forward secrecy** (sigilo futuro): se a chave atual vazar, mensagens **passadas** continuam seguras, pois as chaves antigas já foram descartadas.
- **Post-compromise security** (autocura): mesmo que um atacante comprometa o estado momentaneamente, assim que uma nova troca DH acontece, o protocolo "se cura" e volta a ser seguro.

### HKDF (HMAC-SHA256) — o "moedor" de chaves

HKDF é uma **KDF (Key Derivation Function)**, não uma cifra. Ela pega um segredo de entrada (por exemplo, a saída do ECDH em X25519) — que pode não ter distribuição perfeitamente uniforme — e produz uma ou mais chaves **uniformemente aleatórias e do tamanho certo** para uso específico (ex.: uma chave de 256 bits para o AES-GCM). Funciona em duas etapas:

1. **Extract**: comprime o segredo de entrada em um "pseudorandom key" (PRK) usando HMAC-SHA256.
2. **Expand**: expande esse PRK em quantas chaves forem necessárias, cada uma associada a um contexto/"info" diferente (ex.: "chave de mensagem", "próxima chave de cadeia").

É o HKDF que alimenta cada rodada do Double Ratchet, transformando a saída do X25519 em novas chaves AES-GCM a cada mensagem.

### Como tudo se encaixa (fluxo simplificado)

1. **Estabelecimento inicial** (análogo ao X3DH do Signal): Alice e Bob trocam chaves públicas X25519 (algumas de longo prazo, outras de uso único — *one-time prekeys*) e cada um calcula múltiplos ECDH para gerar um segredo inicial compartilhado.
2. Esse segredo passa pelo **HKDF** e vira a chave raiz (*root key*) do Double Ratchet.
3. A cada mensagem enviada, o **Double Ratchet** (DH ratchet + symmetric ratchet, usando X25519 + HKDF) deriva uma **chave de mensagem** nova.
4. Essa chave de mensagem é usada no **AES-256-GCM** para cifrar o conteúdo e gerar a tag de autenticação.
5. O destinatário refaz os mesmos passos (com sua chave privada) para chegar à mesma chave de mensagem e decifrar/verificar o conteúdo.

---

## 3. Fundamentos matemáticos e cenários de mercado

### AES-256-GCM

#### A cifra de bloco (AES)

AES é uma **rede de substituição-permutação (SPN)**: ela processa blocos fixos de 128 bits e, para uma chave de 256 bits, aplica **14 rodadas** de transformação. Cada rodada mistura o bloco com a chave e o "embaralha" de duas formas complementares:

- **SubBytes**: substitui cada byte por outro, usando uma tabela fixa não linear (S-box). É essa não linearidade que impede ataques puramente algébricos.
- **ShiftRows + MixColumns**: espalham cada byte de entrada pela saída inteira (efeito avalanche — mudar 1 bit da entrada muda ~metade dos bits da saída).
- **AddRoundKey**: `XOR` do bloco com uma subchave derivada da chave original (*key schedule*).

Isso sozinho cifra um bloco de 128 bits por vez. Para cifrar mensagens de qualquer tamanho com segurança, é preciso um **modo de operação** — é aí que entra o GCM.

#### O modo GCM

GCM = **G**alois/**C**ounter **M**ode. Ele faz duas coisas:

1. **Confidencialidade via CTR**: transforma o AES (cifra de bloco) em uma cifra de fluxo. Em vez de cifrar a mensagem diretamente, cifra-se um contador crescente e o resultado é usado como "máscara" (XOR) sobre o texto:

   ```
   Ci = Pi XOR AES_K(nonce || contador_i)
   ```

   Isso permite cifrar/decifrar blocos em paralelo e não precisa de padding.

2. **Autenticidade via GHASH**: calcula uma tag de autenticação combinando todos os blocos cifrados através de uma função de hash universal que opera em **GF(2^128)** (aritmética sobre um corpo finito de 128 bits, análogo a fazer contas em módulo, mas com polinômios binários em vez de números). Qualquer alteração de 1 bit no ciphertext muda completamente a tag — é o que faz a decifração falhar quando alguém adultera a mensagem.

**Por que isso importa**: um modo *não autenticado* (ex.: AES-CBC puro) só cuida da confidencialidade — um atacante pode alterar bytes do ciphertext e o receptor decifraria "lixo" sem perceber a adulteração (isso já causou vulnerabilidades reais, como os ataques de *padding oracle* contra TLS/CBC entre 2010–2016). GCM resolve isso "de graça", motivo pelo qual todo protocolo moderno (TLS 1.3, Signal, SSH) exige modos autenticados (AEAD).

### X25519 (Curvas Elípticas)

#### A curva

X25519 opera sobre uma curva elíptica específica (Curve25519, no formato de Montgomery):

```
y² = x³ + 486662x² + x   (mod p),   onde p = 2²⁵⁵ − 19
```

Os pontos que satisfazem essa equação, mais um "ponto no infinito", formam um **grupo matemático**: dá para "somar" dois pontos da curva e o resultado é outro ponto da curva (geometricamente, é a reflexão do terceiro ponto de interseção entre a reta que liga os dois pontos e a curva). Repetir essa soma `k` vezes a partir de um ponto fixo `G` (ponto gerador, publicamente conhecido) é chamado de **multiplicação escalar**: `k·G`.

#### Por que isso dá segurança

- **Fácil de calcular**: dado `k` (um número, a chave privada) e `G`, calcular `k·G` (a chave pública) é rápido.
- **Difícil de inverter**: dado `G` e `k·G`, descobrir `k` é considerado computacionalmente inviável — esse é o **Problema do Logaritmo Discreto em Curvas Elípticas (ECDLP)**. Não existe algoritmo eficiente conhecido (em computadores clássicos) para resolvê-lo em curvas bem escolhidas como essa.

#### O acordo de chaves (ECDH)

```
Alice: chave privada a, chave pública A = a·G
Bob:   chave privada b, chave pública B = b·G

segredo_Alice = a·B = a·(b·G) = (ab)·G
segredo_Bob   = b·A = b·(a·G) = (ab)·G
```

Como a multiplicação escalar é comutativa nesse grupo, os dois chegam no mesmo ponto `(ab)·G` — que vira o segredo compartilhado — mesmo tendo trocado apenas `A` e `B` publicamente. Um espião que veja `G`, `A` e `B` não consegue reconstruir `(ab)·G` sem resolver o ECDLP.

**Por que curva elíptica em vez de RSA**: para o mesmo nível de segurança, ECC usa chaves muito menores (uma chave de 256 bits em curva elíptica equivale, em força, a uma chave RSA de ~3072 bits) — isso significa handshakes mais rápidos e mais leves, essencial quando se está gerando um par de chaves **novo a cada troca de direção da conversa**, como faz o Double Ratchet.

### HMAC-SHA256 e HKDF

#### HMAC

HMAC transforma uma função de hash comum (SHA-256) em uma função que também depende de uma chave secreta, resistente a um tipo de ataque (*length-extension*) ao qual hashes "puros" como SHA-256 usado ingenuamente seriam vulneráveis:

```
HMAC(K, m) = H( (K' XOR opad) || H( (K' XOR ipad) || m ) )
```

onde `H` é SHA-256, `K'` é a chave ajustada ao tamanho de bloco do hash, e `opad`/`ipad` são constantes fixas. Note a estrutura de "hash duplo": isso é o que dá a garantia de segurança formal do HMAC, mesmo usando um hash que sozinho teria essa fraqueza.

#### HKDF: Extract-and-Expand

```
Extract:  PRK = HMAC(salt, IKM)
Expand:   T(1) = HMAC(PRK, info || 0x01)
          T(2) = HMAC(PRK, T(1) || info || 0x02)
          ...
          OKM  = T(1) || T(2) || ...  (truncado no tamanho desejado)
```

- **Extract** "concentra" um segredo de entrada (IKM — *input key material*, no nosso caso a saída do X25519) numa chave pseudoaleatória de qualidade uniforme.
- **Expand** estica essa chave em quantas chaves forem necessárias, cada uma isolada das outras pelo parâmetro `info` (por isso uma chave derivada para "próxima chave de cadeia" nunca é igual à derivada para "chave de mensagem", mesmo vindo do mesmo segredo).

### Onde essas primitivas aparecem no mercado

| Sistema real | O que usa | Por quê |
|---|---|---|
| **Signal, WhatsApp, Google Messages (RCS)** | X3DH + Double Ratchet (X25519, HKDF, AES-256-GCM) | Exatamente o protocolo estudado neste trabalho — E2EE assíncrono com forward secrecy |
| **TLS 1.3** (HTTPS moderno) | X25519 (ou P-256) para o handshake, **HKDF** para derivar as chaves de sessão (*key schedule*), AES-GCM (ou ChaCha20-Poly1305) para cifrar os dados | O TLS 1.3 usa literalmente a mesma estrutura Extract-and-Expand do HKDF para gerar múltiplas chaves (handshake, aplicação, atualização) a partir de um único segredo ECDH — o mesmo princípio do Double Ratchet, só que sem "girar" a cada mensagem |
| **SSH e assinatura de commits Git** | Ed25519 (irmã do X25519, mesma curva, usada para *assinaturas* em vez de acordo de chave) | Chaves pequenas, geração rápida — por isso GitHub/GitLab recomendam Ed25519 hoje em vez de RSA para chaves SSH |
| **FIDO2 / Passkeys** (login sem senha) | ECC (P-256 ou Ed25519) para assinar desafios de autenticação | Mesma vantagem: chaves pequenas guardadas em hardware seguro (celular, chave de segurança) |
| **PIX / Open Finance Brasil** | mTLS com certificados (RSA ou ECDSA) + OAuth2 no perfil FAPI, assinatura digital nas mensagens (ICP-Brasil) | Cenário diferente: aqui a confiança vem de uma **PKI hierárquica** (certificados emitidos por autoridade certificadora), não de "troca de chaves na primeira conversa" como no Signal — reflete que bancos precisam de identidade *verificável e auditável*, não apenas sigilo ponta a ponta |

#### O padrão que se formou

Existe hoje um "combo" de facto na indústria — **ECC (X25519/Ed25519) + AEAD (AES-GCM/ChaCha20-Poly1305) + HKDF** — que substituiu o combo anterior (RSA + AES-CBC + hash "cru"). A migração aconteceu por razões concretas de mercado:

- **Pós-vazamentos de 2013 (Snowden)**: aumentou a demanda por *forward secrecy* por padrão — TLS 1.3 removeu inclusive o modo RSA estático de troca de chaves, exigindo Diffie-Hellman (efêmero) em toda conexão.
- **Mobile-first**: chaves ECC menores custam menos bateria/CPU/dados — crítico para handshakes de app de mensagens acontecendo o tempo todo em celulares.
- **Incidentes com modos não autenticados** (padding oracle em CBC, ataques a hash sem HMAC) empurraram o mercado para AEAD obrigatório e HKDF em vez de derivação de chave "artesanal".

Esse é o pano de fundo que explica por que a Opção 8 do trabalho ("AES-GCM + X25519/Double Ratchet + HKDF") não é uma escolha arbitrária de disciplina — é reconstruir, em miniatura, o padrão que hoje protege a maior parte do tráfego criptografado do mundo, de mensageria a navegação web.

---

## 4. Implementação: mapeamento teoria → código e limitações

### Onde cada conceito está implementado

| Conceito | Arquivo | O quê |
|---|---|---|
| X25519 (ECDH), AES-256-GCM, HKDF-SHA256 | [`src/crypto_primitives.py`](../src/crypto_primitives.py) | Primitivas puras, sem estado |
| Double Ratchet (DH ratchet + symmetric ratchet) | [`src/double_ratchet.py`](../src/double_ratchet.py) | Classe `DoubleRatchet`, segue o pseudocódigo oficial do Signal |
| Handshake inicial (X25519, análogo simplificado do X3DH) | [`src/client.py`](../src/client.py) (`handshake_alice` / `handshake_bob`) | Um único DH para gerar o segredo inicial |
| Transporte / servidor "zero-trust" | [`src/server.py`](../src/server.py) | Relay TCP que só vê JSON com `ciphertext` opaco |
| Verificação de corretude | [`tests/test_double_ratchet.py`](../tests/test_double_ratchet.py), [`tests/test_network_integration.py`](../tests/test_network_integration.py) | Testes automatizados (pytest) |

### Simplificações em relação ao Signal Protocol real

Estas simplificações foram feitas para manter o escopo viável em um trabalho de disciplina, mas são pontos importantes para discutir na parte teórica (trade-offs de segurança vs. praticidade):

1. **Sem X3DH completo**: o Signal real usa um *identity key* de longo prazo, um *signed prekey* (assinado com XEdDSA) e, opcionalmente, um *one-time prekey*, combinando **3 a 4 DHs** para o segredo inicial. Aqui usamos **um único DH** entre chaves efêmeras geradas na hora. Isso significa que nosso protótipo não oferece autenticação de identidade (qualquer um poderia se passar por Bob na primeira conexão) nem comunicação assíncrona real (ambos precisam estar online ao mesmo tempo para o handshake).
2. **Sem verificação de identidade fora de banda**: o Signal real permite comparar "números de segurança" (*safety numbers*) para detectar ataques *man-in-the-middle* no primeiro contato. Não implementamos isso.
3. **Sem persistência de estado**: o estado do ratchet (chaves de cadeia, chaves puladas) vive apenas em memória durante a execução do processo. Um app real persiste isso em disco de forma criptografada.
4. **Sem header encryption**: o Signal moderno também cifra os cabeçalhos das mensagens (Sesame/Header-encrypted Double Ratchet) para esconder metadados como o número da mensagem. Aqui os cabeçalhos trafegam em claro (apenas o payload é cifrado), o que é o comportamento do Double Ratchet "clássico" descrito na especificação original.
5. **`XEd25519` vs. `X25519` puro**: XEdDSA é uma técnica que permite *assinar* usando uma chave X25519 (reaproveitando o mesmo par de chaves para DH e assinatura). Como nosso handshake não inclui assinaturas de prekeys (não há autenticação), usamos X25519 puro para o acordo de chaves.
6. **Assimetria entre iniciador e respondente**: no Double Ratchet, quem "responde" (Bob, que publicou o prekey) só ganha uma *sending chain* depois de decifrar a primeira mensagem de quem "inicia" (Alice) — é essa mensagem que carrega a nova chave pública de Alice e dispara o primeiro DH ratchet do lado de Bob. Na prática isso significa que **Alice deve enviar a primeira mensagem**; se Bob tentar enviar antes disso, `chain_key_send` ainda é `None` (o cliente detecta esse caso e avisa em vez de travar). Esse comportamento é do protocolo em si, não uma limitação da nossa implementação — vale citar na parte teórica como exemplo de como o design do protocolo molda a UX de um app real (o Signal contorna isso enviando uma mensagem "vazia" de inicialização automaticamente).

### Trade-offs para discutir na parte teórica

- **AES-GCM vs. modos não autenticados (ex.: AES-CBC)**: por que AEAD é obrigatório em qualquer protocolo moderno (integridade "de graça", resistência a *padding oracle attacks*, etc.).
- **Curvas elípticas (X25519) vs. RSA**: chaves muito menores para o mesmo nível de segurança, DH mais rápido, indicado para *ephemeral keys* trocadas a cada sessão/mensagem.
- **Forward secrecy vs. custo computacional**: girar chaves a cada mensagem tem custo de CPU e de sincronização (mensagens fora de ordem, mensagens puladas) — o trade-off entre segurança e complexidade de implementação.
- **HKDF vs. usar o segredo bruto diretamente**: por que nunca se deve usar a saída de um DH diretamente como chave simétrica (não tem garantia de distribuição uniforme; HKDF resolve isso e permite derivar múltiplas chaves independentes do mesmo segredo).
