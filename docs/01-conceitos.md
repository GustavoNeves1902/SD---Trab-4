# Opção 8 — Mensageria Segura Ponto a Ponto (estilo Signal)

> 4º Trabalho de Sistemas Distribuídos
> Tema: Estudo comparativo de primitivas criptográficas e implementação de fluxos de segurança para a garantia da Tríade CIA (Confidencialidade, Integridade e Autenticidade)
> Opção 8: AES-GCM (256 bits) + X25519 (Double Ratchet) + HKDF (HMAC-SHA256)

## Visão geral

Esta opção consiste em recriar, em miniatura, o **Signal Protocol** — o protocolo criptográfico usado pelo Signal, WhatsApp e Google Messages (RCS) para garantir que só o remetente e o destinatário consigam ler as mensagens trocadas, mesmo que o servidor que as transporta seja comprometido (modelo "zero-trust" em relação ao servidor).

A ideia central é combinar três tipos de primitivas criptográficas, cada uma cobrindo uma parte da tríade CIA:

| Primitiva | Tipo | Papel na tríade CIA |
|---|---|---|
| AES-256-GCM | Cifra simétrica autenticada (AEAD) | Confidencialidade + Integridade + Autenticidade da mensagem |
| X25519 (dentro do Double Ratchet) | Criptografia assimétrica (Diffie-Hellman em curva elíptica) | Estabelecimento de segredo compartilhado sem nunca transmiti-lo |
| HKDF (HMAC-SHA256) | Função de derivação de chaves | Transforma segredos "brutos" em chaves de uso específico, renovadas a cada mensagem |

## 1. AES-GCM (256 bits) — a cifra que protege cada mensagem

AES-GCM é uma cifra **simétrica** (a mesma chave cifra e decifra) no modo **Galois/Counter Mode**, que é um modo **AEAD** (Authenticated Encryption with Associated Data). Ele não apenas criptografa o texto, mas também gera uma **tag de autenticação**: se um único bit da mensagem cifrada for alterado em trânsito, a decifração falha.

Com isso, ganha-se:
- **Confidencialidade**: sem a chave, o texto cifrado é ilegível.
- **Integridade / Autenticidade**: qualquer adulteração é detectada (a tag não confere).

O problema prático: como Alice e Bob combinam essa chave simétrica sem nunca trocá-la por um canal inseguro? É aí que entra a parte assimétrica.

## 2. X25519 e o Double Ratchet — como as chaves nascem e mudam

**X25519** é uma curva elíptica usada para **Diffie-Hellman (ECDH)**: cada parte tem um par de chaves (privada/pública) e, ao combinar "minha privada + pública do outro", ambos chegam ao **mesmo segredo**, sem que ele jamais trafegue pela rede. (No enunciado aparece "XEd25519" — é a variante que permite usar as mesmas chaves X25519 tanto para acordo de chave (ECDH) quanto para assinatura, via XEdDSA.)

O **Double Ratchet** (protocolo criado por Trevor Perrin e Moxie Marlinspike) usa X25519 repetidamente para nunca deixar a mesma chave em uso por muito tempo. Ele tem duas "catracas" (ratchets) que só giram para frente, nunca para trás:

- **DH Ratchet**: a cada troca de mensagens em um novo sentido, um novo par de chaves X25519 é gerado e um novo ECDH é feito, alimentando a derivação de chave com material novo.
- **Symmetric-key Ratchet**: dentro de uma mesma "rodada", cada mensagem individual deriva uma chave nova a partir da anterior (uma cadeia de HKDF), então nenhuma mensagem reutiliza a chave da anterior.

Isso dá duas propriedades muito valorizadas em segurança de mensageria:
- **Forward secrecy** (sigilo futuro): se a chave atual vazar, mensagens **passadas** continuam seguras, pois as chaves antigas já foram descartadas.
- **Post-compromise security** (autocura): mesmo que um atacante comprometa o estado momentaneamente, assim que uma nova troca DH acontece, o protocolo "se cura" e volta a ser seguro.

## 3. HKDF (HMAC-SHA256) — o "moedor" de chaves

HKDF é uma **KDF (Key Derivation Function)**, não uma cifra. Ela pega um segredo de entrada (por exemplo, a saída do ECDH em X25519) — que pode não ter distribuição perfeitamente uniforme — e produz uma ou mais chaves **uniformemente aleatórias e do tamanho certo** para uso específico (ex.: uma chave de 256 bits para o AES-GCM). Funciona em duas etapas:

1. **Extract**: comprime o segredo de entrada em um "pseudorandom key" (PRK) usando HMAC-SHA256.
2. **Expand**: expande esse PRK em quantas chaves forem necessárias, cada uma associada a um contexto/"info" diferente (ex.: "chave de mensagem", "próxima chave de cadeia").

É o HKDF que alimenta cada rodada do Double Ratchet, transformando a saída do X25519 em novas chaves AES-GCM a cada mensagem.

## Como tudo se encaixa (fluxo simplificado)

1. **Estabelecimento inicial** (análogo ao X3DH do Signal): Alice e Bob trocam chaves públicas X25519 (algumas de longo prazo, outras de uso único — *one-time prekeys*) e cada um calcula múltiplos ECDH para gerar um segredo inicial compartilhado.
2. Esse segredo passa pelo **HKDF** e vira a chave raiz (*root key*) do Double Ratchet.
3. A cada mensagem enviada, o **Double Ratchet** (DH ratchet + symmetric ratchet, usando X25519 + HKDF) deriva uma **chave de mensagem** nova.
4. Essa chave de mensagem é usada no **AES-256-GCM** para cifrar o conteúdo e gerar a tag de autenticação.
5. O destinatário refaz os mesmos passos (com sua chave privada) para chegar à mesma chave de mensagem e decifrar/verificar o conteúdo.

## Estrutura sugerida do trabalho

- **Parte teórica**: bases matemáticas (curvas elípticas/X25519, AES/GCM, HMAC/HKDF), justificativa de cada escolha frente à tríade CIA, comparação com alternativas (ex.: RSA vs. ECC, modo CBC vs. GCM).
- **Parte prática**: simulador com dois "clientes" (Alice e Bob) trocando mensagens via um "servidor" que apenas repassa bytes cifrados, demonstrando handshake inicial + Double Ratchet + cifragem/decifragem, evidenciando que o servidor não consegue ler o conteúdo.
