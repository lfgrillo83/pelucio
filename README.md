PELUCIO — JS / MAP Recon Tool (pelucio.py)
----------------------------------------------
Resumo: ferramenta para análise automatizada de arquivos .js e .map (remotos e locais)
em busca de possíveis vazamentos: webhooks, chaves AWS, JWTs, tokens, emails, base64 longos,
e agora detecção inteligente de variáveis de senha (senha/pass*).

Principais mudanças na v2.9:
 - Filtros agressivos para reduzir falsos-positivos (assets, CMS ids, image names)
 - long_base64 reforçado (somente base64 puro, sem slashes/dashes)
 - generic_api_key exige entropia >= 4.2 e mistura de classes (lower/upper/digits/symbols)
 - detecta password_like com verificação de entropia e blacklist
 - Não gera arquivo de descartes (filtered_items.json) — saída limpa
 - outputs incluem apenas fontes que geraram *achados* (omit files/urls sem matches)
 - mantém flag --strict para desabilitar filtros (modo barulento)
 - rotação de User-Agent, proxy support, análise de .map automática (até 30MB)
 - CSV adicional com SiteStaticCount (número de strings filtradas como ruído visual)

Avisos: usar apenas em testes autorizados.
