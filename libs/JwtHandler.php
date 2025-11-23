<?php
require_once __DIR__ . '/../config/Core.php';

class JwtHandler {
    protected $secret;

    public function __construct() {
        $this->secret = Core::$jwt_secret;
    }

    public function jwtEncodeData($iss, $data) {
        $token = array(
            "iss" => $iss,
            "aud" => Core::$aud,
            "iat" => Core::$iat,
            "exp" => Core::$exp,
            "data" => $data
        );
        return $this->encode($token, $this->secret);
    }

    public function jwtDecodeData($jwt_token) {
        try {
            $decode = $this->decode($jwt_token, $this->secret);
            return ["data" => $decode->data, "message" => "Token hợp lệ"];
        } catch (Exception $e) {
            return ["message" => $e->getMessage()];
        }
    }

    private function encode($payload, $key) {
        $header = json_encode(['typ' => 'JWT', 'alg' => 'HS256']);
        $payload = json_encode($payload);
        $base64UrlHeader = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
        $base64UrlPayload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));
        $signature = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlPayload, $key, true);
        $base64UrlSignature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));
        return $base64UrlHeader . "." . $base64UrlPayload . "." . $base64UrlSignature;
    }

    private function decode($jwt, $key) {
        $tks = explode('.', $jwt);
        if (count($tks) != 3) throw new Exception('Cấu trúc Token sai.');
        list($headb64, $bodyb64, $cryptob64) = $tks;
        $header = json_decode(base64_decode(str_replace(['-', '_'], ['+', '/'], $headb64)));
        $payload = json_decode(base64_decode(str_replace(['-', '_'], ['+', '/'], $bodyb64)));
        $sig = base64_decode(str_replace(['-', '_'], ['+', '/'], $cryptob64));
        if(!$header || !$payload) throw new Exception('Dữ liệu không hợp lệ');
        $verify = hash_hmac('sha256', "$headb64.$bodyb64", $key, true);
        if (!hash_equals($sig, $verify)) throw new Exception('Token giả mạo!');
        if (isset($payload->exp) && (time() >= $payload->exp)) throw new Exception('Token đã hết hạn.');
        return $payload;
    }
}
?>