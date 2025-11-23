<?php
class Core {
    public static $jwt_secret = "Khoa_Bi_Mat_Cua_Ban_123456"; 
    public static $iss = "http://localhost:8088/LTW_BTL"; 
    public static $aud = "http://localhost:8088/LTW_BTL"; 
    public static $iat; 
    public static $exp; 

    public static function init() {
        self::$iat = time();
        self::$exp = self::$iat + (60 * 60); 
    }
}
Core::init();
?>