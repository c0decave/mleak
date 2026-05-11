<p align="center">
  <img src="branding/logo-256.png" alt="mleak logo" width="160">
</p>

# mleak — OSINT por email para Thunderbird

*Idiomas: [Deutsch](README_DE.md) · [English](README_EN.md) · [Español](README_ES.md) · [Français](README_FR.md) · [Italiano](README_IT.md) · [中文](README_ZH.md) · [हिन्दी](README_HI.md) · [Português](README_PT.md) · [Polski](README_PL.md) · [العربية](README_AR.md) · [Русский](README_RU.md) · [日本語](README_JA.md) · [한국어](README_KO.md) · [Türkçe](README_TR.md) · [Tiếng Việt](README_VI.md) · [Bahasa Indonesia](README_ID.md) · [বাংলা](README_BN.md) · [فارسی](README_FA.md)*

**Fonte:** <https://github.com/c0decave/mleak/>

**Descrição breve.** O mleak é uma extensão do Thunderbird para análise forense dos cabeçalhos e do corpo de cada email. Apresenta impressões digitais do MUA, pilha de servidor, dados de tenant M365, trajeto de relés, veredictos de autenticação, marcadores de listas de email, fugas diretas de IP do remetente, impressões do ordenamento de cabeçalhos, pistas de fronteira MIME, sinais de criptografia e integridade — totalmente offline.

WebExtension para Thunderbird 115+. Analisa cabeçalhos e corpo em base por mensagem e apresenta OSINT estruturado — seja em popup, seja diretamente inline por cima do corpo do email.

- **MUA / cliente**: a partir de `User-Agent`, padrões de `Message-ID`, assinaturas do corpo HTML, parentético de MIME-Version, prefixos de fronteira MIME (Apple-Mail / enig / _000_ / _NextPart_) e ordem dos cabeçalhos autorais — seis sinais independentes, cruzados entre si
- **Pilha de servidor**: Gmail · Exchange/M365 · Apple iCloud · Yahoo · marcadores de entrega (Proofpoint / Mimecast / Barracuda)
- **GUID de tenant M365** + **região do datacenter**: atribuição direta à organização sem whois
- **Trajeto de relés**: contagem de hops, relés externos, **fugas de nomes de host internos** (incl. NetBIOS de rótulo único / nomes de pod k8s), **IPs privados** extraídos de Received (IPv4 + IPv6 ULA / link-local), contexto por hop ("10.x.x.x em relay.example.com via ws-eve.corp.local")
- **Fugas diretas de IP do remetente**: `X-Originating-IP`, `X-Forwarded-For`, `X-Real-IP` e cabeçalhos relacionados, incluindo IPv6 com zona e IPv6 mapeado para IPv4
- **Marcadores de listas de email**: cabeçalhos padrão `List-*` mais impressões Mailman, Sympa, Google Groups, Listserv/LSV e ezmlm
- **Autenticação**: veredictos SPF / DKIM / DMARC / ARC / BIMI + assinaturas DKIM (domínio, selector, indício do fornecedor)
- **Criptografia**: versão do Enigmail (via `X-Enigmail-Version` ou o prefixo de fronteira `enig…`), OpenPGP/MIME, S/MIME, Autocrypt / Autocrypt-Gossip, indicação de keyserver OpenPGP, Symantec PGP-Universal, Tutanota, ProtonMail
- **Integridade**: ausência de Date/MID, divergência From↔Sender, Reply-To em domínio cruzado, lacunas de cobertura h= no DKIM, oversigning
- **Fuso horário**: normalização UTC + offset TZ
- **Estrutura MIME**: impressão digital compacta em árvore com limites de tamanho
- **Visibilidade por cartão**: esconder qualquer um dos sete cartões a partir da página de opções

**100 % offline.** Sem acesso à rede, sem telemetria, sem dependências externas. Os bytes brutos do email nunca saem do processo do Thunderbird.

---

## Instalação

### Temporária (desenvolvimento)
1. `Ferramentas → Extras e Temas → ⚙ → Depurar Extras → Carregar Extra Temporário…`
2. Escolhe `manifest.json` a partir deste diretório.

### Empacotada
```bash
bash pack.sh
# → dist/mleak-<version>.xpi   (atual: 0.6.12)
```
Depois: `Ferramentas → Extras → ⚙ → Instalar Extra a Partir de Ficheiro…` e escolhe o XPI. Para que `xpinstall.signatures.required=false` funcione, a tua compilação do Thunderbird tem de o permitir (compilações de distro como Arch / Debian / ESR normalmente permitem).

---

## Utilização

**Modo popup** continua a ser a predefinição: clica no ícone da barra de ferramentas da mensagem → o popup abre com todos os cartões de OSINT. Opcionalmente, ativa o **modo body-inline** para mostrar o painel mleak automaticamente por cima do corpo do email, sem clicar no ícone. O ícone passa então a mostrar/ocultar esse painel inline.

Abrir definições: `Ferramentas → Extras → mleak → Preferências`. Opções:
- Esquema de cores (automático / escuro / claro)
- Largura do popup (440 / 500 / 600 / 720 px) — 600 é a predefinição
- Densidade (compacta / normal / arejada)
- Vista predefinida (cartões / JSON)
- Modo de apresentação (popup / body-inline por cima do corpo do email)
- Cartões visíveis (esconder qualquer uma das sete categorias)
- Tamanho da cache de análise + botão limpar agora
- Log de depuração (opt-in) + visualizador de log
- Acerca de (versão + convite para contribuir com impressões digitais desconhecidas)

---

## Segurança e privacidade

| Propriedade | Estado |
|---|---|
| Pedidos de rede | **nenhum** (sem `fetch`, `XHR`, `sendBeacon`, `WebSocket`) |
| Injeção DOM | **nenhuma** (apenas `textContent`/`createElement`; sem `innerHTML` com valores dinâmicos) |
| CSP | estrita: `script-src 'self'; object-src 'none'; base-uri 'none'` |
| Permissões | **offline e limitadas**: `messagesRead` + `messagesModify` + `storage` + `tabs` (`messagesModify` apenas para `messageDisplayScripts` do Thunderbird; sem `<all_urls>`) |
| Armazenamento | apenas preferências de UI em `storage.local`; **nenhum conteúdo de email** |
| Log de depuração | opt-in, ring buffer saneado (máx. 500 entradas, strings de estado limitadas, sem cabeçalhos) |
| Proteção ReDoS / fan-out | limites de comprimento em valores de cabeçalho (8 KB), Message-IDs (1 KB), largura da árvore MIME, cabeçalhos repetidos, JSON bruto e linhas de UI |

Cada linha é auditável. Detalhes técnicos, arquitetura dos detetores, modelo de ameaça e instruções de build vivem em [DEVELOPING.md](DEVELOPING.md).

---

## Glossário

Termos que vais ver no popup e no painel inline:

- **MUA** — Mail User Agent; o cliente de email que escreveu a mensagem (Thunderbird, Outlook, Apple Mail, …).
- **Pilha de servidor** — o produto do lado do servidor por onde o email passou (Gmail, Exchange/M365, Apple iCloud, Yahoo, Proofpoint, Mimecast, Barracuda).
- **Tenant M365** — o GUID que o Microsoft 365 imprime nos cabeçalhos de email de saída; identifica diretamente a organização do remetente, sem necessidade de whois.
- **Trajeto de relés** — a lista de servidores externos (hosts `by` na cadeia Received) por onde o email passou, topo = primeiro hop.
- **Fuga de IP privado** — um endereço RFC 1918 (10.x.x.x, 172.16-31.x.x, 192.168.x.x) exposto em cabeçalhos Received; revela a LAN interna do remetente.
- **Fuga de nome de host interno** — um nome de host estilo `.local` / `.corp` / `.internal` / `.lan` em Received; revela a intranet do remetente.
- **Veredictos de autenticação** — pass/fail de SPF, DKIM, DMARC, ARC, BIMI conforme reportados pelo recetor.
- **Impressão do ordenamento de cabeçalhos** — ordem de cabeçalhos autorais como `Subject`, `Date`, `From`, `To`, `Message-ID`; útil para detetar inconsistências no self-report do MUA.
- **Fuga direta de IP do remetente** — IPs do remetente ou de forwarding expostos em `X-Originating-IP`, `X-Forwarded-For`, `X-Real-IP` e cabeçalhos semelhantes. Ranges privados/locais são destacados.
- **Marcador de lista de email** — cabeçalhos `List-*` e específicos de MLM (Mailman, Sympa, Google Groups, Listserv/LSV, ezmlm) que revelam o software da lista e o contexto de publicação.
- **DKIM oversigning** — listar um nome de cabeçalho **várias vezes** na tag `h=` da assinatura DKIM (por exemplo `h=from:from:subject:subject`). Neutraliza ataques de injeção de cabeçalhos: se um relé posterior adicionar um segundo `From:`, a assinatura quebra em vez de validar silenciosamente um cabeçalho forjado.
- **Lacuna de cobertura h= no DKIM** — um cabeçalho relevante para segurança (`From`, `Subject`, `Reply-To`, `Date`, `Message-ID`) *não* está listado na tag `h=` da assinatura, o que significa que pode ser alterado em trânsito sem quebrar a assinatura.
- **Contagem de hops** — número de cabeçalhos Received na cadeia. Saltos abruptos face a uma base são frequentemente prova de forwarding/reescrita de relé.
- **Anomalia cronológica** — carimbos Received que não são monotonicamente decrescentes de cima para baixo; normalmente deriva de relógio de relé, ocasionalmente adulteração.
- **Flags de integridade** — estranhezas estruturais: falta de Date/Message-ID, divergência From↔Sender, Reply-To em domínio cruzado.
- **Enigmail** — o add-on PGP do Thunderbird. Detetado via `X-Enigmail-Version` *ou* via o prefixo de fronteira MIME `-------enig…` (sobrevive à remoção de cabeçalhos).
- **OpenPGP/MIME** — RFC 3156 multipart cifrado/assinado; detetado via `multipart/{encrypted,signed}` + `protocol=application/pgp-*`.
- **S/MIME** — RFC 2633 / PKCS#7 assinado ou cifrado; detetado via tipos de conteúdo `application/(x-)?pkcs7-*`.
- **Autocrypt** — cabeçalho de troca automática de chaves (RFC-draft); a sua presença é um sinal de capacidade do MUA.
- **Pista MUA via fronteira** — os MUAs colocam prefixos específicos do produto nas fronteiras MIME (`Apple-Mail=`, `_000_`, `_NextPart_`, `----=_Part_`). Como a fronteira sobrevive às reescritas de relé, é uma impressão digital útil do MUA — *até em mails cifrados* onde os scanners de HTML não têm nada para inspecionar.

---

## Versões

- **0.6.12** — passagem de endurecimento de segurança e privacidade. Fechados quatro caminhos de poluição de protótipo em `header_order` / `crypto_headers` / `body_html` / `detectors` (uma mensagem com cabeçalho literalmente chamado `constructor` / `__proto__` podia expor uma função JS no painel). `isPrivateIP` agora também reconhece a forma hexadecimal do IPv4-mapeado-em-IPv6 (`::ffff:0a00:0001`) e o antigo `::N.N.N.N`. PII de nomes reais removida dos 100 fixtures de corpus já versionados. Contrato “100 % offline” fixado com cinco testes novos (sem construtores DOM em forma de exfiltração, `target=_blank` precisa de `rel=noopener noreferrer`, URLs de `tabs.create` só via `runtime.getURL`, lista de permissões completa para a superfície `messenger.*`). 0 crashes / 0 violações de schema nos 103 fixtures Tier-1. Veja [CHANGELOG.md](CHANGELOG.md).
- **0.6.5** — build de release para o catálogo OSINT offline expandido e a ronda de hardening: sinais derivados do corpus para Message-ID, clientes, MIME-boundary, listas de email, sender-IP, server-stack e header-order; validação mais estrita de mensagens runtime e IDs de separador/mensagem; debug storage limitado; limites para JSON bruto, renderização UI, fan-out MIME/cabeçalhos e valores de fuga antes de os apresentar. Reconstruído como `dist/mleak-0.6.5.xpi`. Ver [CHANGELOG.md](CHANGELOG.md).
- **0.6.3** — `displayMode` substitui o antigo `inlineMode` (`popup` por predefinição, `bodyInline` selecionável, `headerInline` reservado). Body-inline volta às definições e usa `messageDisplayScripts.register()` para mensagens recém-abertas, mais fallback `executeScript` para separadores já abertos; um retry curto evita a race condition entre `onMessageDisplayed` e o script de visualização acabado de registar. Correção de revisão: `messagesModify` agora é declarado explicitamente porque o Thunderbird o exige para `messageDisplayScripts.*`. O novo smoke test headless verifica que o painel aparece no frame real `browser#messagepane` do Thunderbird. Continua sem acesso à rede.
- **0.6.2** — expansão OSINT offline: impressões do ordenamento de cabeçalhos com verificações de consistência UA, deteção de famílias de fronteira MIME, fingerprints de listas de email, deteção de fugas diretas de IP do remetente, agregação de cabeçalhos de criptografia e apresentação nos resumos popup/inline. Hardening do parser para Authentication-Results repetidos, tags DKIM dobradas ou com variação de maiúsculas/minúsculas, offsets Date com comentários finais, meta generator HTML com atributos invertidos, cabeçalhos sender-IP repetidos, literais IPv6 em `Received`, IPv6 com zona/mapeado, rejeição de IPv6 malformado e renderização MIME com limite de tamanho. O XPI continua sem fazer qualquer acesso à internet.
- **0.5.9** — correção: os ícones da barra de ferramentas e do cabeçalho da mensagem estavam invisíveis porque `icons/logo.svg` usava `stroke="currentColor"` sem contexto CSS ao rasterizar; o manifest inclui agora ícones PNG explícitos em 16/32/48/96 px. Imagens de pré-visualização movidas para `branding/` (não incluídas no XPI).
- **0.5.8** — licenciado sob **MPL-2.0** (LICENSE + cabeçalhos SPDX em cada ficheiro-fonte); i18n expandida para nove idiomas (adicionados zh, hi, pt); os README de utilizador passam a vir em sete idiomas (DE/EN/ES/ZH/HI/PT/PL); LICENSE empacotado dentro do XPI.
- **0.5.6** — documentos de utilizador separados dos de desenvolvedor; o XPI inclui todos os README de utilizador; pipeline de release (`scripts/release.sh`) produz exatamente `.xpi` + `.sha256`, nada mais.
- **0.5.5** — o XPI contém agora `README_DE.md` / `README_EN.md` / `README_ES.md` ao lado do index; teste de regressão impõe o layout.
- **0.5.4** — higiene red-team: o payload on-message em `inline/inline.js` passa a ser validado em forma simétrica a `background.js`; binário do TB resolvido via caminho absoluto para menos uma preocupação com PATH ambiente.
- **0.5.3** — hardening em defesa-em-profundidade: o allowlist `SAFE_HTML_KEYS` em `lib/i18n.js` filtra cada chave `data-i18n-html`; a versão do manifest é validada em formato antes de ser interpolada no innerHTML do cartão About; o ponto de entrada `runtime.onMessage` faz type-check a `msg.type` + `msg.messageId`.
- **0.5.2** — duas correções de correção surgidas em análise estática: `mid_patterns.js` `domain.endsWith("gmail.com")` passa a ser verificação exata-ou-subdomínio; a character class do regex Mutt em `ua_parser.js` foi simplificada (ranges sobrepostos).
- **0.5.1** — UI do modo inline temporariamente desativada (bug de injeção dependente do layout); falhas de detetor passam pelo log de depuração opt-in; IIFE de arranque encapsulada contra promise rejections não tratadas. Passagem por auditoria: sem rede, sem ofuscação, sem código em forma de backdoor, ponto de chamada único de `messages.getFull` controlado pelos nossos próprios tipos de mensagem.
- **0.5.0** — novo detetor `crypto_headers.js` (Enigmail, OpenPGP/MIME, S/MIME, Autocrypt, cabeçalhos de gateway, pistas MUA por prefixo de fronteira). Correções da cadeia Received: análise do parentético by, extração de HELO-bare-IP em `from [IP]`, heurística de nome de host interno de rótulo único com filtro de sentinela, ranges privados em IPv6 (ULA / link-local / mapped). Parentético em MIME-Version como fonte MUA secundária. Corrigido `ReferenceError` latente no loop de relés externos.
- **0.4.2** — captura do parentético no lado by + deteção de host de rótulo único (classe de fugas 1&1 nome-de-pod-Kubernetes / NetBIOS).
- **0.4.1** — ciclo de vida do modo inline reescrito em `onMessageDisplayed` + `tabs.executeScript` com dlog verboso (tentativa de tornar o modo inline fiável; parcialmente bem-sucedida — ainda desativado em 0.5.1).
- **0.4.0** — comutadores de visibilidade por cartão (7 cartões), contexto por hop nas linhas de fuga, trajeto de relés vertical, glossário EN/DE/ES, secção Acerca com CTA de contribuição.
- **0.3.0** — i18n em seis línguas (en/de/es/fr/pl/it), ícone envelope-com-lupa, READMEs multilíngues, `default_locale` definida.
- **0.2.0** — modo inline (tentativa inicial), página de definições, popup responsivo, hardening de segurança (limites de comprimento, proteção ReDoS), logo SVG, renomeação para *mleak*.
- **0.1.0** — release inicial: popup + 9 módulos de detetor.

---

## Contribuir com impressões digitais MUA / servidor desconhecidas

Encontraste um email que a extensão **não conseguiu classificar** — e já sabes de que cliente ou pilha de servidor veio? Envia-nos os cabeçalhos relevantes. São essas contribuições que fazem o catálogo de detetores crescer.

O que enviar:

1. Abre o email, Ver → Origem da Mensagem (ou Ctrl+U).
2. Copia o bloco de cabeçalhos do topo até (e incluindo) a primeira linha em branco — grosseiramente de `Received:` a `Message-ID:`, `User-Agent:`, e qualquer outra coisa que pareça interessante.
3. Nota que cliente / webmail / produto de relé sabes (ou suspeitas) ter originado isto.
4. Podes ofuscar endereços pessoais; **nunca ofusques `Received`, `Message-ID`, `X-*` ou cabeçalhos de autenticação** — são esses que precisamos.
5. Email: **mlux@undisclose.de**, com assunto a começar por `mleak-sample`.

Se preferires Git: abre um issue ou PR em **<https://github.com/c0decave/mleak/>** com a mesma informação.

---

~ Proudly engineered with Claude ~

## Licença

Licenciado sob a **Mozilla Public License 2.0** — ver [LICENSE](LICENSE).

A MPL-2.0 é uma licença copyleft ao nível do ficheiro: modificações a ficheiros MPL têm de permanecer MPL, mas o mleak pode ser livremente combinado com código sob outras licenças (mesmo proprietárias) numa «Larger Work». A licença inclui uma concessão explícita de patente.

Contacto: mlux@undisclose.de
