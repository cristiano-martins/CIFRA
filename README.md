# CIPHER Scanner — Backend API em FastAPI que executa as verificações que o navegador não consegue fazer sozinho: DNS, TLS, WHOIS, reputação (VirusTotal / Safe Browsing) e exposição de e-mail (Have I Been Pwned), sempre com proteção contra SSRF. ## 1. Instalar
bash
cd cipher-backend
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
## 2. Configurar variáveis de ambiente
bash
cp .env.example .env
Preencha as chaves que você já tiver (VIRUSTOTAL_API_KEY, GOOGLE_SAFE_BROWSING_API_KEY, HIBP_API_KEY). **Todas são opcionais.** Sem elas, o endpoint /api/scanner/status reporta essas fontes como não configuradas e o restante da análise (DNS, TLS, WHOIS, heurísticas) continua funcionando normalmente — exatamente como a spec original pede. ## 3. Rodar localmente
bash
uvicorn app.main:app --reload --port 8000
Teste rápido:
bash
curl http://127.0.0.1:8000/
curl -X POST http://127.0.0.1:8000/api/scanner/url \
  -H "Content-Type: application/json" \
  -d '{"url": "example.com"}'
A documentação interativa fica em http://127.0.0.1:8000/docs. ## 4. Ligar ao frontend (CIPHER) O frontend hoje (cipher-scanner.html) roda 100% no navegador e ainda não chama esta API. O próximo passo é trocar as seções marcadas como "requer backend" por chamadas fetch() para: - POST /api/scanner/url { "url": "..." } - POST /api/scanner/domain { "domain": "..." } - POST /api/scanner/email { "email": "..." } - GET /api/scanner/history?limit=30 - GET /api/scanner/report/{id} - DELETE /api/scanner/history/{id} e DELETE /api/scanner/history - GET /api/scanner/status → usar para acender/apagar os indicadores do painel "System Status" dinamicamente, em vez de deixá-los fixos. Me avise quando quiser que eu faça essa ligação — é uma mudança localizada nas funções executarScanURL, executarScanDomain e executarScanEmail do cipher-scanner.html, trocando a heurística local pelo fetch() desses endpoints (mantendo a heurística local como *fallback* caso a API esteja fora do ar, se você quiser resiliência). ## 5. Onde hospedar — sem Linux, sem terminal O GitHub Pages (mencionado no sw.js do frontend) **não roda Python** — serve só arquivos estáticos. O caminho mais simples para o backend, sem precisar instalar nada no seu computador nem usar linha de comando, é **GitHub (upload pelo navegador) + Render (deploy automático)**. ### Passo 1 — Colocar o código no GitHub (sem git, sem terminal) 1. Crie uma conta gratuita em [github.com](https://github.com) (se ainda não tiver). 2. Clique em **New repository**, dê um nome (ex.: cipher-backend), marque como privado se preferir, e clique em **Create repository**. 3. Na página do repositório vazio, clique no link **"uploading an existing file"**. 4. Extraia o cipher-backend.zip no seu computador e **arraste a pasta app/ inteira, mais requirements.txt, render.yaml, .env.example e README.md** para a área de upload do GitHub. 5. Role para baixo e clique em **Commit changes**. Pronto — o código está no GitHub, sem terminal e sem Linux. > Alternativa mais confortável para o dia a dia: instalar o **GitHub > Desktop** (programa com interface gráfica, Windows/Mac) em vez do upload > manual — fica mais fácil enviar atualizações depois. ### Passo 2 — Deploy no Render 1. Crie uma conta gratuita em [render.com](https://render.com) — dá pra entrar direto com a conta do GitHub. 2. Clique em **New +** → **Blueprint** (ou **Web Service**, se preferir configurar manualmente). 3. Selecione o repositório cipher-backend que você acabou de criar. 4. O Render vai detectar o render.yaml automaticamente e sugerir a configuração (Python, pip install -r requirements.txt, comando de início já pronto). Confirme. 5. Na tela seguinte, o Render vai pedir os valores das variáveis marcadas como "secretas" no render.yaml: - VIRUSTOTAL_API_KEY — cole a sua chave (ou deixe em branco) - GOOGLE_SAFE_BROWSING_API_KEY — idem - HIBP_API_KEY — idem (deixe em branco se não for assinar) - CORS_ORIGINS — o endereço de onde o cipher-scanner.html vai ser acessado (ex.: se for GitHub Pages, algo como https://seu-usuario.github.io) 6. Clique em **Apply** / **Create Web Service**. O primeiro deploy leva alguns minutos. 7. Quando terminar, o Render te dá uma URL pública, algo como https://cipher-scanner-api.onrender.com. É essa URL que o frontend vai chamar. ### Limitações do plano gratuito do Render (importante saber) - O serviço **"dorme" após ~15 minutos sem uso** e leva alguns segundos para "acordar" na primeira requisição seguinte — normal em planos gratuitos, não é bug. - **Sem disco persistente**: o arquivo SQLite (cipher.db) é apagado toda vez que o serviço reinicia, dorme/acorda ou recebe um novo deploy — ou seja, o **histórico de scans não sobrevive** entre esses eventos no plano gratuito. As análises em si continuam funcionando normalmente; só o histórico é que não é duradouro. Se isso incomodar, o próximo passo natural é usar um banco gerenciado (o próprio Render tem PostgreSQL gratuito por tempo limitado) — posso te ajudar a migrar quando quiser. ### Se quiser testar no seu computador antes (opcional, funciona no Windows) Você não precisa de Linux — Python roda igual no Windows:
powershell
cd cipher-backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
uvicorn app.main:app --reload --port 8000
(Precisa ter o [Python instalado](https://www.python.org/downloads/) — no instalador, marque a opção "Add Python to PATH".) Depois é só abrir http://127.0.0.1:8000/docs no navegador para testar. ## 6. Limitações conhecidas (documentadas no código) - **DNS rebinding**: a proteção contra SSRF (app/security/ssrf_protection.py) resolve e valida o host antes de cada requisição, o que cobre a grande maioria dos ataques de SSRF. Uma defesa completa contra *rebinding* exigiria pinar a conexão TCP no IP já validado — não implementado aqui por simplicidade. Se for expor publicamente, considere também regras de firewall de saída (egress) permitindo apenas portas 80/443 para IPs públicos. - **Rate limiting em memória**: funciona para um único processo. Ao rodar com múltiplos workers/instâncias, troque por um limitador com estado compartilhado (Redis, por exemplo). - **WHOIS**: cobertura varia por TLD e depende de servidores WHOIS de terceiros, que podem não responder. O código já trata isso como "não disponível", nunca como indício de risco. ## 7. Estrutura
app/
  main.py                  # app FastAPI, CORS, tratamento global de erros
  config.py                 # variáveis de ambiente
  api/scanner.py             # endpoints HTTP
  security/
    validation.py           # formato de URL/domínio/e-mail
    ssrf_protection.py       # bloqueio de IPs internos/privados/metadata
    rate_limit.py            # limite de requisições por IP
  scanner/
    dns_scanner.py           # registros A/AAAA/MX/NS/TXT/CNAME
    tls_scanner.py           # certificado HTTPS
    safe_fetch.py             # HTTP client que segue redirects com validação SSRF a cada salto
    url_scanner.py            # orquestra URL Scanner
    domain_scanner.py         # orquestra Domain Scanner (+ WHOIS opcional)
    email_scanner.py          # orquestra Email Security (+ SPF/DMARC/HIBP)
    reputation_scanner.py     # agrega VirusTotal + Safe Browsing
    risk_engine.py            # único lugar que calcula score/level
  services/
    virustotal.py
    safe_browsing.py
    hibp.py
  database/
    db.py                    # SQLite (tabela `scans`)
