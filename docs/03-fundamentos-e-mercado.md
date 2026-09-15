# Fundamentos matemáticos e cenários de mercado

> Complementa [01-conceitos.md](01-conceitos.md) (visão geral) com a base matemática de cada
> primitiva e exemplos reais de onde ela é usada na indústria — o que o enunciado pede como
> "viabilidade prática... em cenários reais do mercado".

## 1. AES-256-GCM

### A cifra de bloco (AES)

AES é uma **rede de substituição-permutação (SPN)**: ela processa blocos fixos de 128 bits e, para uma chave de 256 bits, aplica **14 rodadas** de transformação. Cada rodada mistura o bloco com a chave e o "embaralha" de duas formas complementares:

- **SubBytes**: substitui cada byte por outro, usando uma tabela fixa não linear (S-box). É essa não linearidade que impede ataques puramente algébricos.
- **ShiftRows + MixColumns**: espalham cada byte de entrada pela saída inteira (efeito avalanche — mudar 1 bit da entrada muda ~metade dos bits da saída).
- **AddRoundKey**: `XOR` do bloco com uma subchave derivada da chave original (*key schedule*).

Isso sozinho cifra um bloco de 128 bits por vez. Para cifrar mensagens de qualquer tamanho com segurança, é preciso um **modo de operação** — é aí que entra o GCM.

### O modo GCM

GCM = **G**alois/**C**ounter **M**ode. Ele faz duas coisas:

1. **Confidencialidade via CTR**: transforma o AES (cifra de bloco) em uma cifra de fluxo. Em vez de cifrar a mensagem diretamente, cifra-se um contador crescente e o resultado é usado como "máscara" (XOR) sobre o texto:

   ```
   Ci = Pi XOR AES_K(nonce || contador_i)
   ```

   Isso permite cifrar/decifrar blocos em paralelo e não precisa de padding.

2. **Autenticidade via GHASH**: calcula uma tag de autenticação combinando todos os blocos cifrados através de uma função de hash universal que opera em **GF(2^128)** (aritmética sobre um corpo finito de 128 bits, análogo a fazer contas em módulo, mas com polinômios binários em vez de números). Qualquer alteração de 1 bit no ciphertext muda completamente a tag — é o que faz a decifração falhar quando alguém adultera a mensagem.

**Por que isso importa**: um modo *não autenticado* (ex.: AES-CBC puro) só cuida da confidencialidade — um atacante pode alterar bytes do ciphertext e o receptor decifraria "lixo" sem perceber a adulteração (isso já causou vulnerabilidades reais, como os ataques de *padding oracle* contra TLS/CBC entre 2010–2016). GCM resolve isso "de graça", motivo pelo qual todo protocolo moderno (TLS 1.3, Signal, SSH) exige modos autenticados (AEAD).

## 2. X25519 (Curvas Elípticas)

### A curva

X25519 opera sobre uma curva elíptica específica (Curve25519, no formato de Montgomery):

```
y² = x³ + 486662x² + x   (mod p),   onde p = 2²⁵⁵ − 19
```

Os pontos que satisfazem essa equação, mais um "ponto no infinito", formam um **grupo matemático**: dá para "somar" dois pontos da curva e o resultado é outro ponto da curva (geometricamente, é a reflexão do terceiro ponto de interseção entre a reta que liga os dois pontos e a curva). Repetir essa soma `k` vezes a partir de um ponto fixo `G` (ponto gerador, publicamente conhecido) é chamado de **multiplicação escalar**: `k·G`.

### Por que isso dá segurança

- **Fácil de calcular**: dado `k` (um número, a chave privada) e `G`, calcular `k·G` (a chave pública) é rápido.
- **Difícil de inverter**: dado `G` e `k·G`, descobrir `k` é considerado computacionalmente inviável — esse é o **Problema do Logaritmo Discreto em Curvas Elípticas (ECDLP)**. Não existe algoritmo eficiente conhecido (em computadores clássicos) para resolvê-lo em curvas bem escolhidas como essa.

### O acordo de chaves (ECDH)

```
Alice: chave privada a, chave pública A = a·G
Bob:   chave privada b, chave pública B = b·G

segredo_Alice = a·B = a·(b·G) = (ab)·G
segredo_Bob   = b·A = b·(a·G) = (ab)·G
```

Como a multiplicação escalar é comutativa nesse grupo, os dois chegam no mesmo ponto `(ab)·G` — que vira o segredo compartilhado — mesmo tendo trocado apenas `A` e `B` publicamente. Um espião que veja `G`, `A` e `B` não consegue reconstruir `(ab)·G` sem resolver o ECDLP.

**Por que curva elíptica em vez de RSA**: para o mesmo nível de segurança, ECC usa chaves muito menores (uma chave de 256 bits em curva elíptica equivale, em força, a uma chave RSA de ~3072 bits) — isso significa handshakes mais rápidos e mais leves, essencial quando se está gerando um par de chaves **novo a cada troca de direção da conversa**, como faz o Double Ratchet.

## 3. HMAC-SHA256 e HKDF

### HMAC

HMAC transforma uma função de hash comum (SHA-256) em uma função que também depende de uma chave secreta, resistente a um tipo de ataque (*length-extension*) ao qual hashes "puros" como SHA-256 usado ingenuamente seriam vulneráveis:

```
HMAC(K, m) = H( (K' XOR opad) || H( (K' XOR ipad) || m ) )
```

onde `H` é SHA-256, `K'` é a chave ajustada ao tamanho de bloco do hash, e `opad`/`ipad` são constantes fixas. Note a estrutura de "hash duplo": isso é o que dá a garantia de segurança formal do HMAC, mesmo usando um hash que sozinho teria essa fraqueza.

### HKDF: Extract-and-Expand

```
Extract:  PRK = HMAC(salt, IKM)
Expand:   T(1) = HMAC(PRK, info || 0x01)
          T(2) = HMAC(PRK, T(1) || info || 0x02)
          ...
          OKM  = T(1) || T(2) || ...  (truncado no tamanho desejado)
```

- **Extract** "concentra" um segredo de entrada (IKM — *input key material*, no nosso caso a saída do X25519) numa chave pseudoaleatória de qualidade uniforme.
- **Expand** estica essa chave em quantas chaves forem necessárias, cada uma isolada das outras pelo parâmetro `info` (por isso uma chave derivada para "próxima chave de cadeia" nunca é igual à derivada para "chave de mensagem", mesmo vindo do mesmo segredo).

## 4. Onde essas primitivas aparecem no mercado

| Sistema real | O que usa | Por quê |
|---|---|---|
| **Signal, WhatsApp, Google Messages (RCS)** | X3DH + Double Ratchet (X25519, HKDF, AES-256-GCM) | Exatamente o protocolo estudado neste trabalho — E2EE assíncrono com forward secrecy |
| **TLS 1.3** (HTTPS moderno) | X25519 (ou P-256) para o handshake, **HKDF** para derivar as chaves de sessão (*key schedule*), AES-GCM (ou ChaCha20-Poly1305) para cifrar os dados | O TLS 1.3 usa literalmente a mesma estrutura Extract-and-Expand do HKDF para gerar múltiplas chaves (handshake, aplicação, atualização) a partir de um único segredo ECDH — o mesmo princípio do Double Ratchet, só que sem "girar" a cada mensagem |
| **SSH e assinatura de commits Git** | Ed25519 (irmã do X25519, mesma curva, usada para *assinaturas* em vez de acordo de chave) | Chaves pequenas, geração rápida — por isso GitHub/GitLab recomendam Ed25519 hoje em vez de RSA para chaves SSH |
| **FIDO2 / Passkeys** (login sem senha) | ECC (P-256 ou Ed25519) para assinar desafios de autenticação | Mesma vantagem: chaves pequenas guardadas em hardware seguro (celular, chave de segurança) |
| **PIX / Open Finance Brasil** | mTLS com certificados (RSA ou ECDSA) + OAuth2 no perfil FAPI, assinatura digital nas mensagens (ICP-Brasil) | Cenário diferente: aqui a confiança vem de uma **PKI hierárquica** (certificados emitidos por autoridade certificadora), não de "troca de chaves na primeira conversa" como no Signal — reflete que bancos precisam de identidade *verificável e auditável*, não apenas sigilo ponta a ponta |

### O padrão que se formou

Existe hoje um "combo" de facto na indústria — **ECC (X25519/Ed25519) + AEAD (AES-GCM/ChaCha20-Poly1305) + HKDF** — que substituiu o combo anterior (RSA + AES-CBC + hash "cru"). A migração aconteceu por razões concretas de mercado:

- **Pós-vazamentos de 2013 (Snowden)**: aumentou a demanda por *forward secrecy* por padrão — TLS 1.3 removeu inclusive o modo RSA estático de troca de chaves, exigindo Diffie-Hellman (efêmero) em toda conexão.
- **Mobile-first**: chaves ECC menores custam menos bateria/CPU/dados — crítico para handshakes de app de mensagens acontecendo o tempo todo em celulares.
- **Incidentes com modos não autenticados** (padding oracle em CBC, ataques a hash sem HMAC) empurraram o mercado para AEAD obrigatório e HKDF em vez de derivação de chave "artesanal".

Esse é o pano de fundo que explica por que a Opção 8 do trabalho ("AES-GCM + X25519/Double Ratchet + HKDF") não é uma escolha arbitrária de disciplina — é reconstruir, em miniatura, o padrão que hoje protege a maior parte do tráfego criptografado do mundo, de mensageria a navegação web.
