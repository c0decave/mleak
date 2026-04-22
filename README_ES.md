# mleak — OSINT por correo para Thunderbird

*Idiomas: [Deutsch](README_DE.md) · [English](README_EN.md) · [Español](README_ES.md) · [中文](README_ZH.md) · [हिन्दी](README_HI.md) · [Português](README_PT.md) · [Polski](README_PL.md)*

**Fuente:** <https://github.com/c0decave/mleak/>

**Descripción breve.** mleak es una extensión de Thunderbird para análisis forense de cabeceras y cuerpo por correo. Extrae la huella del MUA, pila de servidores, datos de tenant M365, ruta de relays, veredictos de autenticación y señales de integridad — totalmente sin conexión.

WebExtension para Thunderbird 115+. Analiza cabeceras y cuerpo por mensaje y muestra inteligencia OSINT estructurada — ya sea en un popup o directamente en línea sobre el cuerpo del correo.

- **MUA / cliente**: a partir de `User-Agent`, patrones de `Message-ID`, firmas del cuerpo HTML, paréntesis de `MIME-Version` y prefijos de MIME-boundary (Apple-Mail / enig / _000_ / _NextPart_) — cinco señales independientes, validación cruzada
- **Pila de servidores**: Gmail · Exchange/M365 · Apple iCloud · Yahoo · marcadores de entrega (Proofpoint / Mimecast / Barracuda)
- **GUID de tenant M365** + **región de datacenter**: atribución directa de la organización sin whois
- **Ruta de relays**: número de saltos, relays externos, **fugas de hostnames internos** (incl. nombres single-label NetBIOS / pods k8s), **IPs privadas** desde Received (IPv4 + IPv6 ULA / link-local), contexto por salto ("10.x.x.x at relay.example.com from ws-eve.corp.local")
- **Autenticación**: veredictos SPF / DKIM / DMARC / ARC / BIMI + firmas DKIM (dominio, selector, pista del proveedor)
- **Crypto**: versión de Enigmail (vía `X-Enigmail-Version` o prefijo de boundary `enig…`), OpenPGP/MIME, S/MIME, Autocrypt / Autocrypt-Gossip, pista de keyserver OpenPGP, Symantec PGP-Universal, Tutanota, ProtonMail
- **Integridad**: Date/MID ausentes, divergencia From↔Sender, Reply-To en dominio cruzado, lagunas de cobertura h= en DKIM, oversigning
- **Zona horaria**: normalización a UTC + desplazamiento TZ
- **Estructura MIME**: huella compacta tipo árbol
- **Visibilidad por tarjeta**: oculta cualquiera de las siete tarjetas desde la página de ajustes

**100 % sin conexión.** Sin acceso a red, sin telemetría, sin dependencias externas. Los bytes crudos del correo nunca salen del proceso de Thunderbird.

---

## Instalación

### Temporal (desarrollo)
1. `Herramientas → Complementos y temas → ⚙ → Depurar complementos → Cargar complemento temporal …`
2. Selecciona `manifest.json` de este directorio.

### Empaquetado
```bash
bash pack.sh
# → dist/mleak-<version>.xpi   (actual: 0.5.8)
```
Luego: `Herramientas → Complementos → ⚙ → Instalar complemento desde archivo …` y elige el XPI. Para que funcione `xpinstall.signatures.required=false`, tu build de Thunderbird debe permitirlo (los builds de distribución tipo Arch / Debian / ESR suelen hacerlo).

---

## Uso

**Modo popup** (predeterminado + actualmente el único modo): clic en el icono de la barra de herramientas del mensaje → se abre el popup con todas las tarjetas de intel. El modo panel-en-línea sigue desactivado mientras se rastrea un bug de inyección específico de ciertos layouts de Thunderbird — las rutas de código permanecen; reactivarlo es un cambio de una línea en cuanto la causa raíz esté clara.

Abrir ajustes: `Herramientas → Complementos → mleak → Preferencias`. Opciones:
- Esquema de color (auto / oscuro / claro)
- Ancho del popup (440 / 500 / 600 / 720 px) — 600 es el predeterminado
- Densidad (compacta / normal / aireada)
- Vista predeterminada (tarjetas / JSON)
- Tarjetas visibles (oculta cualquiera de las siete categorías)
- Tamaño de caché de análisis + botón de limpieza
- Log de depuración (opcional) + visor de log
- Acerca de (versión + llamada a contribuir fingerprints desconocidos)

---

## Seguridad y privacidad

| Propiedad | Estado |
|---|---|
| Peticiones de red | **ninguna** (sin `fetch`, `XHR`, `sendBeacon`, `WebSocket`) |
| Inyección DOM | **ninguna** (solo `textContent`/`createElement`; sin `innerHTML` con valores dinámicos) |
| CSP | estricta: `script-src 'self'; object-src 'none'; base-uri 'none'` |
| Permisos | **mínimos**: solo `messagesRead` + `storage` + `tabs` (sin `messagesModify`, sin `<all_urls>`) |
| Almacenamiento | solo preferencias de UI en `storage.local`; **sin contenido de correos** |
| Log de depuración | opt-in, ring buffer (máx. 500 entradas, solo cadenas de estado, sin cabeceras) |
| Protección ReDoS | topes de longitud en valores de cabecera (8 KB) + Message-IDs (1 KB) antes del match de regex |

Cada línea es auditable. Detalles técnicos, arquitectura de detectores, modelo de amenazas y guía de compilación están en [DEVELOPING.md](DEVELOPING.md).

---

## Glosario

Términos que verás en el popup y el panel en línea:

- **MUA** — Mail User Agent; el cliente de correo que redactó el mensaje (Thunderbird, Outlook, Apple Mail, …).
- **Server Stack** — el producto del lado servidor por el que pasó el correo (Gmail, Exchange/M365, Apple iCloud, Yahoo, Proofpoint, Mimecast, Barracuda).
- **M365 Tenant** — el GUID que Microsoft 365 imprime en las cabeceras salientes; identifica la organización del remitente directamente, sin whois.
- **Relay path** — la lista de servidores externos (`by`-hosts en la cadena Received) por los que pasó el correo; arriba = primer salto.
- **Private IP leak** — una dirección RFC 1918 (10.x.x.x, 172.16–31.x.x, 192.168.x.x) expuesta en cabeceras Received; filtra la LAN interna del remitente.
- **Internal hostname leak** — un hostname con sufijo `.local` / `.corp` / `.internal` / `.lan` en Received; filtra la intranet del remitente.
- **Auth verdicts** — veredictos SPF, DKIM, DMARC, ARC, BIMI pass/fail según informa el receptor.
- **DKIM oversigning** — listar un nombre de cabecera **varias veces** en el tag `h=` de la firma DKIM (p. ej. `h=from:from:subject:subject`). Defiende contra inyección de cabeceras: si un relay posterior añade un segundo `From:`, la firma se rompe en vez de validar silenciosamente una cabecera forjada.
- **DKIM h=-coverage gap** — una cabecera relevante (`From`, `Subject`, `Reply-To`, `Date`, `Message-ID`) *no* está listada en el tag `h=`, lo que permite alterarla en tránsito sin invalidar la firma.
- **Hop count** — número de cabeceras Received en la cadena. Saltos repentinos frente a una línea base son evidencia frecuente de reenvíos / reescrituras por relay.
- **Chronology anomaly** — las marcas de tiempo Received no decrecen monótonamente de arriba abajo; normalmente desfase de reloj entre relays, a veces manipulación de la cadena.
- **Integrity flags** — rarezas estructurales: falta Date/Message-ID, divergencia From↔Sender, Reply-To con dominio cruzado.
- **Enigmail** — el add-on PGP de Thunderbird. Detectado vía `X-Enigmail-Version` *o* vía el prefijo de boundary MIME `-------enig…` (sobrevive al stripping de cabeceras).
- **OpenPGP/MIME** — RFC 3156 multipart cifrado/firmado; detectado vía `multipart/{encrypted,signed}` + `protocol=application/pgp-*`.
- **S/MIME** — RFC 2633 / PKCS#7 firmado o cifrado; detectado vía tipos `application/(x-)?pkcs7-*`.
- **Autocrypt** — cabecera del RFC-draft para intercambio automático de claves; su presencia es señal de capacidad del MUA.
- **Pista de MUA por boundary** — los MUA estampan prefijos específicos de producto en boundaries MIME (`Apple-Mail=`, `_000_`, `_NextPart_`, `----=_Part_`). Como el boundary sobrevive a reescrituras de relays, es una huella de MUA útil **incluso en correos cifrados**, donde los scanners de body-HTML no tienen nada que inspeccionar.

---

## Versiones

- **0.5.8** — licenciado bajo **MPL-2.0** (LICENSE + cabeceras SPDX en cada fichero fuente); i18n ampliada a nueve idiomas (añadidos zh, hi, pt); los READMEs de usuario se incluyen ahora en siete idiomas (DE/EN/ES/ZH/HI/PT/PL); LICENSE empaquetado dentro del XPI.
- **0.5.6** — docs de usuario separadas de docs de desarrollo; el XPI incluye los tres READMEs idiomáticos; pipeline de release (`scripts/release.sh`) produce exactamente `.xpi` + `.sha256`, nada más.
- **0.5.5** — el XPI contiene ahora `README_DE.md` / `README_EN.md` / `README_ES.md` junto al índice; test de regresión asegura el layout.
- **0.5.4** — higiene red-team: `inline/inline.js` valida el shape del payload simétrico a `background.js`; binario TB resuelto con ruta absoluta — un riesgo de PATH ambiental menos.
- **0.5.3** — endurecimiento defense-in-depth: allowlist `SAFE_HTML_KEYS` protege cada clave `data-i18n-html` en `lib/i18n.js`; versión del manifest validada por formato antes de ir a innerHTML en la tarjeta "Acerca de"; entrada `runtime.onMessage` chequea tipos de `msg.type` + `msg.messageId`.
- **0.5.2** — dos correcciones menores del análisis estático: `mid_patterns.js` usa ahora exact-or-subdomain para `domain.endsWith("gmail.com")`; regex Mutt en `ua_parser.js` tenía character class con rangos solapados, simplificado.
- **0.5.1** — UI del modo en línea temporalmente desactivada (bug de inyección por layout); los fallos de detector se canalizan por el log de depuración opt-in; IIFE de arranque protegido contra rechazos de promesas no manejados. Auditoría de seguridad: sin red, sin ofuscación, sin código tipo puerta trasera, `messages.getFull` con un único call-site detrás de tipos de mensaje propios.
- **0.5.0** — nuevo detector `crypto_headers.js` (Enigmail, OpenPGP/MIME, S/MIME, Autocrypt, cabeceras de gateway, pistas MUA por prefijo de boundary). Correcciones en cadena Received: parseo del by-parenthetical, extracción de HELO-bare-IP `from [IP]`, heurística de hostname interno single-label con filtro de sentinel, rangos privados IPv6 (ULA / link-local / mapped). Paréntesis de MIME-Version como fuente secundaria de MUA. `ReferenceError` latente en el bucle de relay externo corregido.
- **0.4.2** — captura del by-parenthetical + detección de hostnames single-label (clase de leak de pod k8s / NetBIOS de 1&1).
- **0.4.1** — reescritura del ciclo de vida inline sobre `onMessageDisplayed` + `tabs.executeScript` con dlog detallado (intento de estabilizar el modo en línea; parcialmente exitoso — aún así desactivado en 0.5.1).
- **0.4.0** — visibilidad por tarjeta (7 tarjetas), contexto por salto en las fugas, ruta de relays vertical, glosario en EN/DE/ES, sección "Acerca de" con CTA para contribuir.
- **0.3.0** — i18n en seis idiomas (en/de/es/fr/pl/it), icono sobre+lupa, READMEs multilingües, `default_locale` declarado.
- **0.2.0** — modo en línea (primer intento), página de ajustes, popup responsivo, endurecimiento de seguridad (topes de longitud, protección ReDoS), logo SVG, renombrado a *mleak*.
- **0.1.0** — lanzamiento inicial: popup + 9 módulos de detectores.

---

## Contribuye huellas de MUA / servidor desconocidas

¿Encontraste un correo que la extensión **no pudo clasificar** — y ya sabes qué cliente o pila de servidor lo generó? Envíanos las cabeceras relevantes. Esas contribuciones son la forma en que crece el catálogo de detectores.

Qué enviar:

1. Abre el correo, Ver → Código fuente del mensaje (o Ctrl+U).
2. Copia el bloque superior de cabeceras hasta la primera línea en blanco — aproximadamente desde `Received:` pasando por `Message-ID:`, `User-Agent:` y cualquier otra que parezca interesante.
3. Anota qué cliente / webmail / producto de relay crees (o sabes) que lo generó.
4. Puedes redactar direcciones personales; **nunca redactes `Received`, `Message-ID`, `X-*` ni cabeceras de autenticación** — son justo las que necesitamos.
5. Correo: **mlux@undisclose.de**, asunto empezando con `mleak-sample`.

Si prefieres Git: abre una issue o PR en **<https://github.com/c0decave/mleak/>**.

---

~ Proudly "agentic engineered" with Claude ~

## Licencia

Licenciado bajo la **Mozilla Public License 2.0** — véase [LICENSE](LICENSE).

MPL-2.0 es una licencia copyleft a nivel de archivo: las modificaciones a los archivos MPL deben seguir siendo MPL, pero mleak puede combinarse libremente con código bajo otras licencias (incluso propietario) en una «Larger Work». La licencia incluye una concesión explícita de patente.

Contacto: mlux@undisclose.de
