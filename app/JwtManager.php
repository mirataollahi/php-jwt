<?php

namespace App;
class JwtManager
{

    /**
     * @var string
     */
    private string $secretKey;

    /**
     * @var string
     */
    private string $algorithm;

    /**
     * @var string
     */
    private string $signatureAlgorithm;

    /**
     * @var string
     */
    private string $tokenType;

    /**
     * @var string
     */
    private string $expirationTime;

    public function __construct(string $secretKey , string|null $algorithm = 'HS256' , string|null $tokenType = 'jwt' , $signatureAlgorithm = 'sha256' ,int  $expTime = 3600)
    {
        $this->setSecretKey($secretKey);
        $this->setAlgorithm($algorithm);
        $this->setTokenType($tokenType);
        $this->setExpirationTime($expTime);
        $this->setSignatureAlgorithm($signatureAlgorithm);
    }

    /**
     * Set jwt manager private token
     *
     * @param string $secretKey
     * @return $this
     */
    public function setSecretKey(string $secretKey): static
    {
        $this->secretKey = $secretKey;
        return $this;
    }

    /**
     * Set jwt manger secret key
     *
     * @return string
     */
    public function getSecretKey(): string
    {
        return $this->secretKey;
    }

    /**
     * Set jwt manager algorithm
     *
     * @param string $algorithm
     * @return $this
     */
    public function setAlgorithm(string $algorithm = 'HS256'): static
    {
        $this->algorithm = $algorithm;
        return $this;
    }

    /**
     * Get jwt manager algorithm
     *
     * @return string
     */
    public function getAlgorithm(): string
    {
        return $this->algorithm;
    }

    /**
     * @param string $signatureAlgorithm
     * @return static
     */
    public function setSignatureAlgorithm(string $signatureAlgorithm = 'sha256'): static
    {
        $this->signatureAlgorithm = $signatureAlgorithm;
        return $this;
    }

    /** Get signature algorithm
     *
     * @return string
     */
    public function getSignatureAlgorithm(): string
    {
        return $this->signatureAlgorithm;
    }

    /**
     * Set jwt manager token type
     *
     * @param string $tokenType
     * @return $this
     */
    public function setTokenType(string $tokenType = 'JWT'): static
    {
        $this->tokenType = ucfirst($tokenType);
        return $this;
    }

    /**
     * Get token type
     *
     * @return string
     */
    public function getTokenType(): string
    {
        return $this->tokenType;
    }

    /**
     * Get expiration time
     *
     * @return int
     */
    public function getExpirationTime(): int
    {
        return $this->expirationTime;
    }

    /**
     * @param int $expirationTime
     * @return $this
     */
    public function setExpirationTime(int $expirationTime = 3600): static
    {
        $this->expirationTime = $expirationTime;
        return $this;
    }

    /**
     *
     * @return string
     */
    public function encodeHeader(): string
    {
        return base64_encode(json_encode([
            'alg' => $this->getAlgorithm(),
            'typ' => $this->getTokenType()
        ]));
    }

    /**
     * Encode payload before
     *
     * @param string|int|array|null $data
     * @param int|null $expirationTime
     * @return string
     */
    public function encodePayload(string|int|array|null $data , int|null $expirationTime = null): string
    {
        $expirationTime = $expirationTime ?: $this->getExpirationTime();

        return base64_encode(json_encode([
            'exp' => time() + $expirationTime ,
            'data' => $data
        ]));
    }


    /**
     * decode jwt token payload payload
     *
     * @param $payload
     * @return array|null
     */
    public function decodePayload($payload): array|null
    {
        return json_decode(
            base64_decode($payload
            ), true);
    }

    /**
     * Generate signature
     *
     * @param string $header
     * @param string $payload
     * @return string
     */
    public function makeSignature(string $header , string $payload): string
    {
        return base64_encode(hash_hmac(
            $this->getSignatureAlgorithm(),
            "$header.$payload",
            $this->secretKey,
            true
        ));
    }

    /**
     * Generate a jwt token
     *
     * @param string|int|array|null $data
     * @param int $expiration
     * @return string
     */
    public function generateToken(string|int|array|null $data, int $expiration = 3600): string
    {
        $header = $this->encodeHeader();
        $payload = $this->encodePayload($data , $expiration);
        $signature = $this->makeSignature(
            header:$header ,
            payload: $payload
        );
        return "$header.$payload.$signature";
    }

    public function parsToken(string $token): array
    {
        list($header, $payload, $signature) = explode('.', $token);
        return [
            'header' => $header ,
            'payload' => $payload ,
            'signature' => $signature ,
        ];
    }

    /**
     * Validate a jwt token base on the private key
     *
     * @param string|null $token
     * @return array|bool|string
     */
    public function validateToken(string|null $token = null):array|bool|string
    {
        $parsedToken = $this->parsToken($token);
        $data = $this->decodePayload($parsedToken['payload']);

        $expectedSignature = $this->makeSignature(
            header:$parsedToken['header'] ,
            payload:$parsedToken['payload'] ,
        );

        if (hash_equals($expectedSignature, base64_decode($parsedToken['signature'])) && $data['exp'] > time()) {
            return $data['data'];
        }

        return false;
    }


}