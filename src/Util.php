<?php


namespace Oh86\TelecomCryptor;


use GuzzleHttp\Client;
use Oh86\Sm\Sm3;

class Util
{
    public static function hmacSm3(string $data, string $key): string
    {
        return hmac_sm3($data, $key);
    }

    /**
     * @return Client
     */
    public static function newHttpClient(): Client
    {
        $client = new Client([
            "verify" => false,
        ]);
        return $client;
    }
}
