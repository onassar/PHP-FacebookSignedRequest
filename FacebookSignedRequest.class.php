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
         * @var     string
         * @access  protected
         */
        protected $_appSecret;

        /**
         * _encodedSignature
         * 
         * @var     string
         * @access  protected
         */
        protected $_encodedSignature;

        /**
         * _payload
         * 
         * @var     array (default: array())
         * @access  protected
         */
        protected $_payload = array();

        /**
         * _signature
         * 
         * @var     string
         * @access  protected
         */
        protected $_signature;

        /**
         * _signedRequest
         * 
         * @var     string
         * @access  protected
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
            $decoded = base64_decode(strtr($str, '-_', '+/'));
            return $decoded;
        }

        /**
         * _parsePayload
         * 
         * @access  protected
         * @return  bool
         */
        protected function _parsePayload(): bool
        {
            $payload = $this->_payload;
            if (empty($payload) === false) {
                return false;
            }
            $signedRequest = $this->_signedRequest;
            list($encodedSignature, $encodedPayload) = explode(
                '.',
                $signedRequest,
                2
            );
            $this->_signature = $this->_base64URLDecode($encodedSignature);
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
            $this->_parsePayload();
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
            $signature = $this->_signature;
            $valid = $signature === $hash;
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
            $this->_parsePayload();
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

