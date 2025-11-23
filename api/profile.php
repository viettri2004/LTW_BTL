<?php
header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Methods: GET");
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

require_once '../libs/JwtHandler.php';

$headers = apache_request_headers();
$authHeader = null;

if (isset($headers['Authorization'])) {
    $authHeader = $headers['Authorization'];
} elseif (isset($headers['authorization'])) {
    $authHeader = $headers['authorization'];
}

if (!empty($authHeader)) {
    try {
        $arr = explode(" ", $authHeader);
        $jwt = isset($arr[1]) ? $arr[1] : "";

        if ($jwt) {
            $jwtHandler = new JwtHandler();
            $result = $jwtHandler->jwtDecodeData($jwt);

            if (isset($result['data'])) {
                http_response_code(200);
                echo json_encode(array(
                    "message" => "Truy cập thành công.",
                    "data" => $result['data']
                ));
            } else {
                http_response_code(401);
                echo json_encode(array("message" => $result['message']));
            }
        } else {
            throw new Exception("Token không tìm thấy.");
        }
    } catch (Exception $e) {
        http_response_code(401);
        echo json_encode(array("message" => "Truy cập bị từ chối. " . $e->getMessage()));
    }
} else {
    http_response_code(401);
    echo json_encode(array("message" => "Vui lòng cung cấp Token."));
}
?>