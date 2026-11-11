<?php
// seguranca.php  -  incluir NO TOPO de todo arquivo PHP (antes de config.php)

if (session_status() === PHP_SESSION_NONE) {
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'httponly' => true,                    // JavaScript não consegue ler o cookie da sessão
        'samesite' => 'Lax',                   // navegador não envia o cookie em requisições de outros sites
        'secure'   => !empty($_SERVER['HTTPS']) // só HTTPS quando o site estiver em https
    ]);
    session_start();
}

header('X-Frame-Options: DENY');              // ninguém pode colocar seu painel dentro de um iframe (clickjacking)
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');

// e() = "escapar". Transforma <script> em texto inofensivo. Use em TUDO que vem do usuário/banco.
function e($v): string {
    return htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

// ---------- CSRF ----------
function csrf_token(): string {
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function csrf_campo(): string {
    return '<input type="hidden" name="csrf" value="' . e(csrf_token()) . '">';
}

function csrf_valido(): bool {
    return isset($_POST['csrf'], $_SESSION['csrf'])
        && hash_equals($_SESSION['csrf'], (string)$_POST['csrf']);
}

// ---------- Erro amigável (já seguro contra XSS) ----------
function voltar_com_erro(string $msg) {
    echo '<script>alert(' . json_encode($msg, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) . '); window.history.back();</script>';
    exit;
}
