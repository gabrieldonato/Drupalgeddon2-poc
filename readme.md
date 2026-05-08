# Drupalgeddon2 - REST API / HAL+JSON PoC (CVE-2018-7600)

Proof of Concept simples para exploração do Drupalgeddon2 (CVE-2018-7600) usando o endpoint REST/HAL+JSON do Drupal.

O script envia um payload serializado via `PATCH` para um node existente e executa comandos no servidor através da cadeia `FnStream` + `HandlerStack`.

> Uso exclusivo para ambientes autorizados, labs, estudos e CTFs.

---

## Requisitos

- Python 3
- requests

---

## Uso

```bash
python3 drupalgeddon2.py <base_url> <node_id> <command>
```

Exemplos:

```bash
python3 drupalgeddon2.py http://target.local 1 "id"
```

```bash
python3 drupalgeddon2.py http://target.local 1 "cat /etc/passwd"
```

---

## Como funciona

O script:

1. Abre uma sessão HTTP
2. Obtém um CSRF token em `/rest/session/token`
3. Monta o payload HAL+JSON com o objeto serializado
4. Envia um `PATCH` para:

```text
/node/<id>?_format=hal_json
```

5. Extrai a saída do comando usando marcadores:

```text
====START====
====END====
```

---

## Observações

- O endpoint REST precisa estar habilitado
- O node informado deve existir
- O payload usa bytes nulos reais (`\x00`) na serialização PHP
- Algumas versões/configurações do Drupal podem responder diferente dependendo dos módulos instalados

---

## Estrutura

```text
get_csrf_token()  -> obtém CSRF token
build_payload()   -> monta payload serializado
exploit_node()    -> envia PATCH e processa resposta
main()            -> CLI
```

---

