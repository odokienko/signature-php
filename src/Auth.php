<?php namespace PhilipBrown\Signature;

use PhilipBrown\Signature\Guards\CheckKey;
use PhilipBrown\Signature\Guards\CheckVersion;
use PhilipBrown\Signature\Guards\CheckTimestamp;
use PhilipBrown\Signature\Guards\CheckSignature;

class Auth
{
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
    private $params;

    /**
     * @var array
     */
    private $auth = [
        'auth_key',
        'auth_version',
        'auth_timestamp',
        'auth_signature'
    ];
    
    public $to_sign;
    
    /**
     * Create a new Auth instance
     *
     * @param string $method
     * @param strign $uri
     * @param array $params
     * @return void
     */
    public function __construct($method, $uri, array $params)
    {
        $this->method = strtoupper($method);
        $this->uri    = $uri;
        $this->params = $params;

        $this->guards = [
            new CheckVersion,
            new CheckKey,
            new CheckTimestamp,
            new CheckSignature
        ];
    }

    /**
     * Attempt to authenticate a request
     *
     * @param Token $token
     * @return bool
     */
    public function attempt(Token $token)
    {
        $auth = $this->getAuthParams();

        $body = $this->getBodyParams();

        $response   = new Response($this->method, $this->uri, $body, $auth);
        $signature = $response->sign($token);

        foreach ($this->guards as $guard) {
            $guard->check($auth, $signature);
        }

        return true;
    }
    
    /**
     * Attempt to authenticate a request
     *
     * @param Token $token
     * @return bool
     */
    public function debug_attempt(Token $token)
    {
        $auth = $this->getAuthParams();

        $body = $this->getBodyParams();

        $response   = new Response($this->method, $this->uri, $body, $auth);
        

        $signature = $response->sign($token);
        
        $this->to_sign = $response->to_sign;
        
        return $signature;
    }

    /**
     * Get the auth params
     *
     * @return array
     */
    public function getAuthParams()
    {
        return array_intersect_key($this->params, array_flip($this->auth));
    }

    /**
     * Get the body params
     *
     * @return array
     */
    public function getBodyParams()
    {
        return array_diff_key($this->params, array_flip($this->auth));
    }
}
