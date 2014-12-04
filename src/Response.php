<?php namespace PhilipBrown\Signature;

//use Carbon\Carbon;

class Response
{
    /**
     * @var string
     */
    private $version = '3.0';

    /**
     * @var string
     */
    private $method;

    /**
     * @var string
     */
    private $uri;

    /**
     * @var array
     */
    public $to_sign;

    /**
     * Create a new Request
     *
     * @param string $method
     * @param string $uri
     * @param array $params
     */
    public function __construct($method, $uri, array $body, array $auth)
    {
        $this->method = strtoupper($method);
        $this->uri    = $uri;
        $this->body = $body;
        $this->auth = $auth;
    }

    /**
     * Sign the Request with a Token
     *
     * @param Token $token
     * @return array
     */
    public function sign(Token $token)
    {
        $auth = [
            'auth_version'   => $this->version,
            'auth_key'       => $token->key(),
            'auth_timestamp' => !empty($this->auth['auth_timestamp']) ? $this->auth['auth_timestamp'] : 0
        ];
        
        $payload = $this->payload($auth, $this->body);
        
        $signature = $this->signature($payload, $this->method, $this->uri, $token->secret());

        $auth['auth_signature'] = $signature;
        return $auth;
    }

    /**
     * Create the payload
     *
     * @param array $auth
     * @param array $params
     * @return array
     */
    public function payload(array $auth, array $params)
    {
        $payload = array_merge($auth, $params);

        array_change_key_case($payload, CASE_LOWER);

        ksort($payload);

        return $payload;
    }

    /**
     * Create the signature
     *
     * @param array $payload
     * @param string $method
     * @param string $uri
     * @param string $secret
     * @return string
     */
    public function signature(array $payload, $method, $uri, $secret)
    {
        $payload = urldecode(http_build_query($payload));

        $payload = implode("\n", [$method, $uri, $payload]);
        
        $this->to_sign = $payload;
        
        return hash_hmac('sha256', $payload, $secret);
    }
}
