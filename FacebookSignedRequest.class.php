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
         * _data
         * 
         * @var     array (default: array())
         * @access  protected
         */
        protected $_data = array();

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
         * @param   string $signedRequest
         * @param   string $appSecret
         * @return  void
         */
        public function __construct(string $signedRequest, string $appSecret)
        {
            $this->_signedRequest = $signedRequest;
            $this->_appSecret = $appSecret;
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
         * _valid
         * 
         * @access  protected
         * @return  bool
         */
        protected function _valid(): bool
        {
            // Decode and set the payload
            $signedRequest = $this->_signedRequest;
            list($encodedSignature, $encodedPayload) = explode(
                '.',
                $signedRequest,
                2
            );
            $payload = $this->_base64URLDecode($encodedPayload);
            $this->_data = json_decode($payload, true);

            // Ensure proper encoding algorithm and signature
            $valid = $this->_validAlgorithm();
            if ($valid === false) {
                return false;
            }
            $signature = $this->_base64URLDecode($encodedSignature);
            $valid = $this->_validSignature($signature, $payload);
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
            $algorithm = $this->_data['algorithm'];
            $valid = strtoupper($algorithm) === 'HMAC-SHA256';
            LogUtils::log($valid);
            return $valid;
        }

        /**
         * _validSignature
         * 
         * @access  protected
         * @param   string $signature
         * @param   string $payload
         * @return  bool
         */
        protected function _validSignature(string $signature, string $payload): bool
        {
            $args = func_get_args();
            LogUtils::log($args);
            $appSecret = $this->_appSecret;
            LogUtils::log($appSecret);
            $hash = hash_hmac('sha256', $payload, $appSecret, true);
            LogUtils::log($hash);
            $valid = $signature === $hash;
            LogUtils::log($valid);
            return $valid;
        }

        /**
         * getData
         * 
         * @access  public
         * @return  array
         */
        public function getData(): array
        {
            $data = $this->_data;
            return $data;
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

