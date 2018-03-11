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
         * _base64UrlDecode
         * 
         * @access  protected
         * @param   string $str
         * @return  string
         */
        protected function _base64UrlDecode($str)
        {
            return base64_decode(strtr($str, '-_', '+/'));
        }

        /**
         * _confirmSignature
         * 
         * @throws  Exception
         * @access  protected
         * @param   string $signature
         * @param   string $payload
         * @return  string
         */
        protected function _confirmSignature($signature, $payload)
        {
            $expectedSignature = hash_hmac(
                'sha256',
                $payload,
                $this->_appSecret,
                $raw = true
            );
            if ($signature !== $expectedSignature) {
                throw new Exception('Bad Signed JSON signature!');
            }
        }

        /**
         * _confirmValidAlgorithm
         * 
         * @throws  Exception
         * @access  protected
         * @return  string
         */
        protected function _confirmValidAlgorithm()
        {
            if (strtoupper($this->_data['algorithm']) !== 'HMAC-SHA256') {
                throw new Exception('Unknown algorithm. Expected HMAC-SHA256');
            }
        }

        /**
         * _parse
         * 
         * @access  protected
         * @return  void
         */
        protected function _parse()
        {
            // Decode the payload
            list($encodedSignature, $payload) = explode(
                '.',
                $this->_signedRequest,
                2
            );
            $signature = $this->_base64UrlDecode($encodedSignature);
            $this->_data = json_decode($this->_base64UrlDecode($payload), true);

            // Ensure proper encoding algorithm and signature
            $this->_confirmValidAlgorithm();
            $this->_confirmSignature($signature, $payload);
        }

        /**
         * __construct
         * 
         * @access  public
         * @param   string $signedRequest
         * @param   string $appSecret
         * @return  void
         */
        public function __construct($signedRequest, $appSecret)
        {
            $this->_signedRequest = $signedRequest;
            $this->_appSecret = $appSecret;
            $this->_parse();
        }

        /**
         * getData
         * 
         * @access  public
         * @return  array
         */
        public function getData()
        {
            return $this->_data;
        }
    }

