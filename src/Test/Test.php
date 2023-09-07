<?php


namespace Oh86\TelecomCryptor\Test;


use Oh86\TelecomCryptor\Cryptor;

class Test
{
    public static function testGetAccessToken() {
        $encryptor = new Cryptor([
            "host" => env("TELECOM_ENCRYPTOR_HOST"),
            "ak" => env("TELECOM_ENCRYPTOR_AK"),
            "sk" => env("TELECOM_ENCRYPTOR_SK"),
            "sm4_key_index" => env("TELECOM_ENCRYPTOR_SM4_KEY_INDEX"),
            "hmac_key_index" => env("TELECOM_ENCRYPTOR_HMAC_KEY_INDEX"),
        ]);

        $accessToken = $encryptor->getAccessToken();
        var_dump($accessToken);
    }

    public static function testSm4Encrypt() {
        $encryptor = new Cryptor([
            "host" => env("TELECOM_ENCRYPTOR_HOST"),
            "ak" => env("TELECOM_ENCRYPTOR_AK"),
            "sk" => env("TELECOM_ENCRYPTOR_SK"),
            "sm4_key_index" => env("TELECOM_ENCRYPTOR_SM4_KEY_INDEX"),
            "hmac_key_index" => env("TELECOM_ENCRYPTOR_HMAC_KEY_INDEX"),
        ]);

        $enText = $encryptor->sm4Encrypt("测试abc");
        // 941ca24ed3f832d6f87452630c7f3980
        var_dump($enText);
    }

    public static function testSm4Decrypt() {
        $encryptor = new Cryptor([
            "host" => env("TELECOM_ENCRYPTOR_HOST"),
            "ak" => env("TELECOM_ENCRYPTOR_AK"),
            "sk" => env("TELECOM_ENCRYPTOR_SK"),
            "sm4_key_index" => env("TELECOM_ENCRYPTOR_SM4_KEY_INDEX"),
            "hmac_key_index" => env("TELECOM_ENCRYPTOR_HMAC_KEY_INDEX"),
        ]);

        $text = $encryptor->sm4Decrypt("941ca24ed3f832d6f87452630c7f3980");
        var_dump($text);
    }

    public static function testHMAC() {
        $encryptor = new Cryptor([
            "host" => env("TELECOM_ENCRYPTOR_HOST"),
            "ak" => env("TELECOM_ENCRYPTOR_AK"),
            "sk" => env("TELECOM_ENCRYPTOR_SK"),
            "sm4_key_index" => env("TELECOM_ENCRYPTOR_SM4_KEY_INDEX"),
            "hmac_key_index" => env("TELECOM_ENCRYPTOR_HMAC_KEY_INDEX"),
        ]);

        $hmac = $encryptor->hmac("abc");
        var_dump($hmac);
    }
}
