# Pelucio — Sourcemap & JavaScript Analyzer

**Pelucio** é uma ferramenta voltada para _security researchers_, _bug hunters_ e _red teamers_ que desejam identificar possíveis vazamentos de informações sensíveis em arquivos **JavaScript** e **Source Maps (.map)** expostos na web.

Desenvolvido em Python, o Pelucio mantém a lógica do antigo `sourcemap_extractor` com diversas melhorias de desempenho, detecção e filtragem de falsos-positivos.

---

## 🚀 Principais recursos

- 🔎 **Detecção automática de leaks** em arquivos `.js` e `.map`
- 🔄 **Busca recursiva** de dependências JavaScript (até 3 níveis)
- 🗺️ Suporte completo a **sourcemaps inline e remotos**
- 🧩 Identificação de:
  - Chaves privadas (`PRIVATE KEY`)
  - Credenciais AWS (`AWS_SECRET_KEY`, `AWS_ACCESS_KEY`)
  - Webhooks do Slack
  - JWTs (com decodificação automática)
  - Tokens, senhas e strings Base64 suspeitas
- 🧰 Geração automática de artefatos:
  - `pelucio_findings.json` — resultados completos (metadados + payloads decodificados)
  - `pelucio_findings.csv` — findings ordenados por criticidade
  - `pelucio_urls.txt` — URLs descobertas
  - `pelucio_wordlist.txt` — caminhos para uso com ferramentas como `ffuf`, `gobuster`, etc.
- 🧼 Redução de falsos-positivos (exclusão de fontes, CSS vars, Angular Material, etc.)
- ⚙️ Execução paralela com **ThreadPoolExecutor**
- 📊 Barra de progresso e banner informativo

---

## 📦 Instalação

```bash
git clone https://github.com/lfgrillo83/pelucio.git
cd pelucio
pip install -r requirements.txt
