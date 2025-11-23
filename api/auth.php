<?php
// --- CẤU HÌNH CORS ---
if (isset($_SERVER['HTTP_ORIGIN'])) {
    header("Access-Control-Allow-Origin: {$_SERVER['HTTP_ORIGIN']}");
    header('Access-Control-Allow-Credentials: true');
    header('Access-Control-Max-Age: 86400');
}

if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    if (isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_METHOD']))
        header("Access-Control-Allow-Methods: GET, POST, OPTIONS");         
    if (isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS']))
        header("Access-Control-Allow-Headers: {$_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS']}");
    exit(0);
}

header("Content-Type: application/json; charset=UTF-8");

require_once '../config/Database.php';
require_once '../libs/JwtHandler.php';

$db = new Database();
$conn = $db->getConnection();

$data = json_decode(file_get_contents("php://input"));

if (!empty($data->username) && !empty($data->password)) {
    
    $query = "SELECT id, name, username, password, status FROM customer WHERE username = :username LIMIT 1";
    $stmt = $conn->prepare($query);
    $stmt->bindValue(':username', $data->username);
    $stmt->execute();

    if ($stmt->rowCount() > 0) {
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        
        $check_password = password_verify($data->password, $row['password']);

        if(!$check_password && $data->password == $row['password']) {
             $check_password = true; 
        }   

        if ($check_password) {
            if($row['status'] == 'banned') {
                http_response_code(403);
                echo json_encode(["message" => "Tài khoản của bạn đã bị khóa."]);
                exit;
            }

            $jwt = new JwtHandler();
            $token = $jwt->jwtEncodeData(
                "http://localhost:8088/Assignment_Web",
                array(
                    "user_id" => $row['id'],
                    "name" => $row['name'],
                    "username" => $row['username'],
                    "role" => "customer"
                )
            );

            http_response_code(200);
            echo json_encode(array(
                "message" => "Đăng nhập thành công.",
                "token" => $token,
                "user" => array(
                    "name" => $row['name']
                )
            ));
        } else {
            http_response_code(401);
            echo json_encode(array("message" => "Mật khẩu không chính xác."));
        }
    } else {
        http_response_code(401);
        echo json_encode(array("message" => "Tên đăng nhập không tồn tại."));
    }
} else {
    http_response_code(400);
    echo json_encode(array("message" => "Vui lòng nhập đầy đủ thông tin."));
}
?>