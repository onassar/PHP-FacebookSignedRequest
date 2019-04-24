<?php

    /**
     * FacebookSignedRequest
     * 
     * Validates that a signed request was passed using the correct algorithm,
     * by Facebook, parses the request, and gives quick access to the resulting
     * data.
     * 
     * @see     http://stackoverflow.com/questions/4859820/facebook-user-deauthorizes-the-app
     * @see     https://developers.facebook.com/docs/facebook-login/using-login-with-games/
     * @see     https://developers.facebook.com/docs/reference/login/signed-request/
     * @link    https://github.com/onassar/PHP-FacebookSignedRequest
     * @author  Oliver Nassar <onassar@gmail.com>
     */
    class FacebookSignedRequest
    {
        /**
         * _appSecret
         * 
         * @access  protected
         * @var     string
         */
        protected $_appSecret;

        /**
         * _encodedSignature
         * 
         * @access  protected
         * @var     string
         */
        protected $_encodedSignature;

        /**
         * _parsed
         * 
         * @access  protected
         * @var     bool (default: false)
         */
        protected $_parsed = false;

        /**
         * _payload
         * 
         * @access  protected
         * @var     array (default: array())
         */
        protected $_payload = array();

        /**
         * _signedRequest
         * 
         * @access  protected
         * @var     string
         */
        protected $_signedRequest;

        /**
         * __construct
         * 
         * @access  public
         * @param   string $appSecret
         * @param   string $signedRequest
         * @return  void
         */
        public function __construct(string $appSecret, string $signedRequest)
        {
            $this->_appSecret = $appSecret;
            $this->_signedRequest = $signedRequest;
        }

        /**
         * _base64URLDecode
         * 
         * @access  protected
         * @param   string $str
         * @return  string
         */
        protected function _base64URLDecode(string $str): string
        {
            $str = strtr($str, '-_', '+/');
            $decoded = base64_decode($str);
            return $decoded;
        }

        /**
         * _getDecodedSignature
         * 
         * @access  protected
         * @return  string
         */
        protected function _getDecodedSignature(): string
        {
            $encodedSignature = $this->_encodedSignature;
            $decodedSignature = $this->_base64URLDecode($encodedSignature);
            return $decodedSignature;
        }

        /**
         * _parseSignedRequest
         * 
         * @access  protected
         * @return  bool
         */
        protected function _parseSignedRequest(): bool
        {
            $parsed = $this->_parsed;
            if ($parsed === true) {
                return false;
            }
            $this->_parsed = true;
            $signedRequest = $this->_signedRequest;
            list($encodedSignature, $encodedPayload) = explode(
                '.',
                $signedRequest,
                2
            );
            $this->_encodedSignature = $encodedSignature;
            $this->_encodedPayload = $encodedPayload;
            $payload = $this->_base64URLDecode($encodedPayload);
            $payload = json_decode($payload, true);
            $this->_payload = $payload;
            return true;
        }

        /**
         * _valid
         * 
         * @access  protected
         * @return  bool
         */
        protected function _valid(): bool
        {
            $this->_parseSignedRequest();
            $valid = $this->_validAlgorithm();
            if ($valid === false) {
                return false;
            }
            $valid = $this->_validSignature();
            if ($valid === false) {
                return false;
            }
            return true;
        }

        /**
         * _validAlgorithm
         * 
         * @access  protected
         * @return  bool
         */
        protected function _validAlgorithm(): bool
        {
            $payload = $this->_payload;
            $algorithm = $payload['algorithm'];
            $valid = strtoupper($algorithm) === 'HMAC-SHA256';
            return $valid;
        }

        /**
         * _validSignature
         * 
         * @access  protected
         * @return  bool
         */
        protected function _validSignature(): bool
        {
            $encodedPayload = $this->_encodedPayload;
            $appSecret = $this->_appSecret;
            $hash = hash_hmac('sha256', $encodedPayload, $appSecret, true);
            $decodedSignature = $this->_getDecodedSignature();
            $valid = $decodedSignature === $hash;
            return $valid;
        }

        /**
         * getPayload
         * 
         * @access  public
         * @return  array
         */
        public function getPayload(): array
        {
            $this->_parseSignedRequest();
            $payload = $this->_payload;
            return $payload;
        }

        /**
         * valid
         * 
         * @access  public
         * @return  bool
         */
        public function valid(): bool
        {
            $valid = $this->_valid();
            return $valid;
        }
    }

