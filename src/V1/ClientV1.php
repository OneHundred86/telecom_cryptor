<?php


namespace Oh86\TelecomCryptor\V1;


use Oh86\TelecomCryptor\Exceptions\DecryptException;
use Oh86\TelecomCryptor\Exceptions\EncryptException;
use Oh86\TelecomCryptor\Exceptions\FetchTokenException;
use Oh86\TelecomCryptor\Exceptions\HMACException;
use Oh86\TelecomCryptor\Util;

class ClientV1
{
    private string $host;
    private string $ak;
    private string $sk;

    public function __construct(array $config) {
        $this->host = $config["host"];
        $this->ak = $config["ak"];
        $this->sk = $config["sk"];
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws FetchTokenException
     */
    public function getToken() : array {
        $client = Util::newHttpClient();

        $url = sprintf("%s/ccsp-iam/v1/api/token", $this->host);
        $ak = $this->ak;
        $sk = base64_decode($this->sk);
        $grantType = "client_credentials";
        $timeStr = now("UTC")->format("YmdHis") . ".000Z";
        $m = sprintf("%s%s%s", $ak, $timeStr, $grantType);
        $mac = strtoupper(Util::hmacSm3($m, $sk));
        $response = $client->post($url, [
            "json" => [
                "accessKey" => $ak,
                "mac" => $mac,
                "grantType" => $grantType,
                "timestamp" => $timeStr,
            ],
        ]);

        // {"code":200,"data":{"expiresIn":3600,"scope":"eds-28 eds-11 svs-60 eds-21 eds-52 svs-53 svs-10 tsa-13","accessToken":"eyJhbGciOiJTTTJTTTMiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiJiMjliNTA0ZTdiZjNjMDQyY2E1ZmM2NTJmMjQ4N2ZjZSIsImF1ZCI6WyJiMjliNTA0ZTdiZjNjMDQyY2E1ZmM2NTJmMjQ4N2ZjZSJdLCJuYmYiOjE2ODUzNTYxNDksInNjb3BlIjpbImVkcy0yOCIsImVkcy0xMSIsInN2cy02MCIsImVkcy0yMSIsImVkcy01MiIsInN2cy01MyIsInN2cy0xMCIsInRzYS0xMyJdLCJpc3MiOiJodHRwczovLzM2LjE0MC42Ni4xMTo5NDQzL2Njc3AtaWFtIiwiZXhwIjoxNjg1MzU5NzQ5LCJpYXQiOjE2ODUzNTYxNDksImp0aSI6IjQxMWQ4ZjA4LTY1ZTktNGRjYy1hODYwLTkxMmU4ZWVmMmVhNiJ9.MEQCIDP5fpZiyp/yDW5cafJuzOC0VMj+VWQkAnAfdRM2sRrzAiAH1UiddJGLQvPdSTD8MHMPT+tlpPnSHAfHuyB744E4qg==","tokenType":"Bearer"},"msg":""}
        // {"code":1007000007,"data":null,"msg":"invalid client: Client authentication failed: 客户端计算的 mac 值错误。"}
        $contents = $response->getBody()->getContents();
        // echo $contents . PHP_EOL;
        $jsonArr = json_decode($contents, true);
        if (($jsonArr["code"] ?? false) != 200) {
            throw new FetchTokenException($contents, $response->getStatusCode());
        }

        return $jsonArr["data"];
    }

    private function appendAuthorizationHeaders(array $headers, string $accessToken): array
    {
        $headers["X-ACCESS-KEY"] = $this->ak;
        $headers["Authorization"] = sprintf("Bearer %s", $accessToken);
        return $headers;
    }

    public function encrypt(string $text, string $accessToken, int $keyIndex, string $algo, ?string $iv = null, ?string $aad = null) :array
    {
        $client = Util::newHttpClient();

        $url = sprintf("%s/eds-52/ccsp-eds/api/v1/encrypt", $this->host);
        $response = $client->post($url, [
            "headers" => $this->appendAuthorizationHeaders([], $accessToken),
            "json" => [
                "keyIndex" => $keyIndex,
                "plainText" => $text,
                "algo" => $algo,
                "iv" => $iv,
                "aad" => $aad,
            ],
        ]);

        // {"code":200,"data":{"cipherText":"lByiTtP4Mtb4dFJjDH85gA==","tag":null,"iv":null},"msg":""}
        // {"code":2000400000,"data":null,"msg":"请求参数不正确: IV[iv]长度不正确"}
        $content = $response->getBody()->getContents();
        // echo $content . PHP_EOL;
        $jsonArr = json_decode($content, true);
        if (($jsonArr["code"] ?? false) != 200){
            throw new EncryptException($content, $response->getStatusCode());
        }

        return $jsonArr["data"];
    }

    public function decrypt(string $cipherText, string $accessToken, int $keyIndex, string $algo, ?string $iv = null, ?string $aad = null, ?string $tag = null) : array
    {
        $client = Util::newHttpClient();

        $url = sprintf("%s/eds-52/ccsp-eds/api/v1/decrypt", $this->host);
        $response = $client->post($url, [
            "headers" => $this->appendAuthorizationHeaders([], $accessToken),
            "json" => [
                "keyIndex" => $keyIndex,
                "cipherText" => $cipherText,
                "algo" => $algo,
                "iv" => $iv,
                "aad" => $aad,
                "tag" => $tag,
            ],
        ]);

        // {"code":200,"data":{"plainText":"5rWL6K+VYWJj"},"msg":""}
        $content = $response->getBody()->getContents();
        // echo $content . PHP_EOL;
        $jsonArr = json_decode($content, true);
        if (($jsonArr["code"] ?? false) != 200) {
            throw new DecryptException($content, $response->getStatusCode());
        }

        return $jsonArr["data"];
    }

    public function hmac(string $message, string $accessToken, int $keyIndex, string $algo) : array
    {
        $client = Util::newHttpClient();
        $url = sprintf("%s/eds-52/ccsp-eds/api/v1/hmac", $this->host);
        $response = $client->post($url, [
            "headers" => $this->appendAuthorizationHeaders([], $accessToken),
            "json" => [
                "keyIndex" => $keyIndex,
                "message" => $message,
                "algo" => $algo,
            ],
        ]);

        // {"code":200,"data":{"mac":"55e315d244b3678ba736521f097d8e5e0c8862f974bb32265568ec5dfd9577f1"},"msg":""}
        // {"code":2000404000,"data":null,"msg":"密钥不存在"}
        $content = $response->getBody()->getContents();
        // echo $content . PHP_EOL;
        $jsonArr = json_decode($content, true);
        if (($jsonArr["code"] ?? false) != 200) {
            throw new HMACException($content, $response->getStatusCode());
        }

        return $jsonArr["data"];
    }
}
