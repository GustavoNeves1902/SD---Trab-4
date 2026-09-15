# Como funciona, em termos simples

> Versão didática, para quem não tem background em criptografia. Para a explicação técnica
> completa (com nomes de algoritmos, funções e trade-offs), ver [01-conceitos.md](01-conceitos.md)
> e [02-implementacao-e-limitacoes.md](02-implementacao-e-limitacoes.md).

Pense em Alice e Bob como duas pessoas trocando bilhetes através de um carteiro (o **servidor**) que não é necessariamente confiável — ele pode ler tudo que passa pelas mãos dele, então os bilhetes precisam estar dentro de uma caixa trancada que só o destinatário consegue abrir.

## 1. O "cadeado mágico" (X25519 / Diffie-Hellman)

Cada pessoa cria um par **cadeado + chave**: guarda a chave para si (privada) e manda o cadeado aberto para o outro (pública). Isso sozinho não resolveria o problema — mas existe um truque matemático (Diffie-Hellman) que permite uma coisa incrível:

> Alice pega **sua própria chave privada** + **o cadeado público do Bob**, faz uma continha, e chega em um número secreto.
> Bob pega **sua própria chave privada** + **o cadeado público da Alice**, faz a mesma continha, e chega **no mesmo número secreto**.

Ninguém mais consegue chegar nesse número só vendo os cadeados públicos passarem pelo carteiro — é como se cada um misturasse uma tinta secreta com uma tinta pública, trocassem as misturas, e só eles conseguissem "desfazer" a mistura para chegar na mesma cor final. Esse número secreto compartilhado é a base de tudo — e nenhum dos dois nunca o enviou pela rede.

No código, isso é a função `dh()` em [crypto_primitives.py](../src/crypto_primitives.py).

## 2. O "liquidificador de chaves" (HKDF)

Esse número secreto do passo 1 é meio "torto" — não tem a qualidade ideal para ser usado direto como senha de um cadeado real. Então ele passa por um liquidificador (HKDF) que:
- Transforma esse número em uma chave bem "lisa" e aleatória.
- Consegue tirar **várias chaves diferentes** do mesmo segredo, cada uma para um uso específico (uma para trancar mensagens, outra para continuar a corrente de chaves, etc.).

É a função `hkdf()` no mesmo arquivo, e é usada o tempo todo dentro do ratchet.

## 3. A "caixa lacrada" (AES-256-GCM)

Com uma chave boa em mãos, a mensagem é colocada numa caixa trancada com um lacre especial:
- Sem a chave, ninguém abre a caixa (**confidencialidade**).
- Se alguém tentar violar o lacre no caminho — trocar uma única letra da mensagem — o lacre quebra visivelmente e o destinatário percebe a violação em vez de ler algo adulterado (**integridade/autenticidade**).

No teste `test_tampered_ciphertext_is_rejected`, alteramos um byte da mensagem cifrada de propósito e o sistema recusou abrir a caixa.

## 4. A parte "estilo Signal": nunca reusar a mesma chave (Double Ratchet)

Aqui está o pulo do gato que diferencia isso de uma cifra comum. Ao invés de Alice e Bob usarem **a mesma chave para sempre**, a cada mensagem enviada:

- Gira-se uma **catraca** (ratchet — como a catraca de ônibus, só anda para frente) que transforma a chave atual numa chave nova, e descarta a antiga.
- Isso significa que se alguém roubar a chave de hoje, **as mensagens de ontem continuam seguras** — as chaves antigas já foram destruídas (isso se chama *forward secrecy*, sigilo para frente).

E, de tempos em tempos (toda vez que a conversa muda de direção — de "Alice fala" para "Bob responde"), eles fazem um **novo aperto de mão com cadeados novos** (repetem o passo 1 com chaves frescas), misturando essa novidade na corrente de chaves. Isso significa que, mesmo que um atacante consiga espiar um pedacinho da conversa, o sistema "se cura" sozinho pouco depois (*post-compromise security*).

## O que acontece, na prática, na nossa implementação

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

Um detalhe curioso, descoberto testando o sistema de verdade: no passo 4, o Bob só ganha "permissão" para responder depois de abrir a primeira caixa da Alice. Se ele tentar escrever antes disso, o sistema ainda não tem a chave pronta — o cliente detecta esse caso e avisa em vez de travar. Isso não é uma falha da implementação: é assim que o Double Ratchet real funciona — quem "atende" a conversa precisa ouvir algo primeiro antes de poder falar (ver item 6 de [02-implementacao-e-limitacoes.md](02-implementacao-e-limitacoes.md)).

## E o carteiro (servidor) nessa história?

Ele só vê caixas lacradas passando de um lado para o outro — sabe *quem* mandou, *para quem*, e *o tamanho* da caixa, mas nunca consegue abrir nenhuma. É exatamente o que aparece no log do servidor: `"repassando 288 bytes... (conteúdo ilegível para o servidor)"`.
