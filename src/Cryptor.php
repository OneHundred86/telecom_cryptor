<?php


namespace Oh86\TelecomCryptor;


use Illuminate\Support\Facades\Cache;
use Oh86\TelecomCryptor\V1\ClientV1;

class Cryptor
{
    private array $config;
    private ClientV1 $client;

    /**
     * @param array{host: string, ak: string, sk: string, eds_node: string, svs_node: string, sm4_key_index: int, hmac_key_index: int} $config
     */
    public function __construct(array $config) {
        $this->config = $config;
        $this->client = new ClientV1($config);
    }

    /**
     * @throws Exceptions\FetchTokenException
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function getAccessToken() :string {
        $cacheKey = "telecom_encrypt_token";
        if(($data = Cache::get($cacheKey))) {
            return $data["accessToken"];
        }

        $data = $this->client->getToken();
        Cache::put($cacheKey, $data, now()->addSeconds($data["expiresIn"] - 60));

        return $data["accessToken"];
    }

    /**
     * @param string $text :: 原始字符串
     * @param string $algo
     * @return string :: hex编码
     * @throws Exceptions\EncryptException
     * @throws Exceptions\FetchTokenException
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function sm4Encrypt(string $text, string $algo = "SGD_SM4_ECB") : string
    {
        $data = $this->client->encrypt(base64_encode($text), $this->getAccessToken(), $this->config["sm4_key_index"], $algo);
        $bin = base64_decode($data["cipherText"]);
        return bin2hex($bin);
    }

    /**
     * @param string $cipherText :: hex编码
     * @param string $algo
     * @return string
     * @throws Exceptions\DecryptException
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws Exceptions\FetchTokenException
     */
    public function sm4Decrypt(string $cipherText, string $algo = "SGD_SM4_ECB") : string
    {
        $cipherText = base64_encode(hex2bin($cipherText));
        $data = $this->client->decrypt($cipherText, $this->getAccessToken(), $this->config["sm4_key_index"], $algo);
        return base64_decode($data["plainText"]);
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws Exceptions\HMACException
     * @throws Exceptions\FetchTokenException
     */
    public function hmac(string $text, string $algo = "SGD_SM3_HMAC") : string
    {
        $cipherText = base64_encode($text);
        $data = $this->client->hmac($cipherText, $this->getAccessToken(), $this->config["hmac_key_index"], $algo);
        return $data["mac"];
    }
}
