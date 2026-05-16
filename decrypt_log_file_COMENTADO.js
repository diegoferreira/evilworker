// Importa o módulo nativo "fs" do Node.js para leitura de arquivos de log do disco.
const fs = require("fs");
// Importa o módulo nativo "crypto" do Node.js para operações de descriptografia AES.
const crypto = require("crypto");


// Chave de criptografia AES-256-CTR — deve corresponder à mesma chave usada no proxy_server.js.
// AVISO: deve ser alterada e armazenada de forma segura em engajamentos reais.
const ENCRYPTION_KEY = "HyP3r-M3g4_S3cURe-EnC4YpT10n_k3Y";


// Obtém os argumentos passados na linha de comando (node decrypt_log_file.js <caminho_do_log>).
const clArguments = process.argv;
// Valida que exatamente um argumento adicional foi fornecido (o caminho do arquivo de log).
if (clArguments.length !== 3) {
    // Exibe mensagem de uso correto e encerra com código de erro se os argumentos estiverem incorretos.
    console.error(`/!\ Usage: ${clArguments[0]} ${clArguments[1]} $ENCRYPTED_LOG_FILE_PATH /!\\`);
    process.exit(1);
}

// Chama a função de descriptografia passando o caminho do arquivo como argumento.
const decryptedLogFile = decryptLogFile(clArguments[2]);
// Exibe o conteúdo descriptografado no terminal.
console.log(decryptedLogFile);

// Função que descriptografa um único bloco de dados usando AES-256-CTR.
// Recebe o IV (vetor de inicialização) em hexadecimal e os dados cifrados também em hex.
function decryptData(iv, encryptedData) {
    try {
        // Cria o objeto de descriptografia AES-256-CTR com a chave fixa e o IV fornecido.
        // Buffer.from(iv, "hex") converte o IV de string hex para Buffer binário.
        const decipher = crypto.createDecipheriv("aes-256-ctr", ENCRYPTION_KEY, Buffer.from(iv, "hex"));

        // Descriptografa os dados (entrada em hex, saída em UTF-8).
        let decryptedData = decipher.update(encryptedData, "hex", "utf-8");
        // Finaliza a descriptografia e concatena o bloco final.
        decryptedData += decipher.final("utf-8");

        // Retorna o dado descriptografado como string UTF-8.
        return decryptedData;
    }
    catch (error) {
        // Lança erro com mensagem descritiva se a descriptografia falhar.
        throw new Error(`Log file decryption failed: ${error.message}`);
    }
}

// Função principal que lê e descriptografa o arquivo de log inteiro linha por linha.
function decryptLogFile(logFilePath) {
    try {
        // Verifica se o arquivo de log existe antes de tentar lê-lo.
        if (!fs.existsSync(logFilePath)) {
            throw new Error(`The ${logFilePath} file does not exist`);
        }
        // Lê o arquivo completo como UTF-8 e divide em linhas (cada linha é uma entrada de log cifrada).
        const encryptedLogs = fs.readFileSync(logFilePath, "utf8").split("\n");
        let decryptedData = ""; // Acumula o texto descriptografado de todas as entradas

        // Itera sobre cada linha do arquivo de log.
        for (const encryptedLog of encryptedLogs) {
            // Ignora linhas vazias ou compostas apenas de espaços.
            if (!encryptedLog.trim()) continue;
            // Parseia a linha como JSON — cada entrada tem formato { "<iv_hex>": "<dados_cifrados_hex>" }.
            const encryptedEntry = JSON.parse(encryptedLog);
            // Extrai o par [iv, dadosCifrados] usando Object.entries com desestruturação.
            const [[iv, encryptedData]] = Object.entries(encryptedEntry);
            // Descriptografa a entrada e concatena ao resultado final.
            decryptedData += decryptData(iv, encryptedData);
        }
        // Retorna toda a string descriptografada (contém credenciais, cookies, requests capturados).
        return decryptedData;

    } catch (error) {
        // Exibe qualquer erro ocorrido durante a leitura ou descriptografia.
        console.error(error);
    }
}
