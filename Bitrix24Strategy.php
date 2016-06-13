<?php

class Bitrix24Strategy extends OpauthStrategy
{
    public $expects = array('app_id', 'app_secret', 'domain');
    public $optionals = array('redirect_uri', 'scope');
    public $defaults = array(
        'redirect_uri' => '{complete_url_to_strategy}oauth2callback',
        'scope' => array("user", "crm")
    );

    public function request()
    {
        $url = 'https://' . $this->strategy['domain'] . '/oauth/authorize/';
        $params = array(
            'client_id' => $this->strategy['app_id'],
            'redirect_uri' => $this->strategy['redirect_uri'],
            'response_type' => 'code'
        );

        foreach ($this->optionals as $key) {
            if (!empty($this->strategy[$key])) {
                $params[$key] = $this->strategy[$key];
            }
        }

        $this->serverGet($url, $params);
    }

    public function oauth2callback()
    {
        if (array_key_exists('code', $_GET) && !empty($_GET['code'])) {
            $code = $_GET['code'];
            $url = 'https://' . $this->strategy['domain'] . '/oauth/token/';
            $params = array(
                'client_id' => $this->strategy['client_id'],
                'client_secret' => $this->strategy['client_secret'],
                'code' => $code,
                'redirect_uri' => $this->strategy['redirect_uri'],
                'grant_type' => 'authorization_code',
                'scope' => $this->strategy['scope']
            );

            $response = $this->serverGet($url, $params, null, $headers);
            $results = json_decode($response, true);

            if (!empty($results) && !empty($results['access_token'])) {


                $this->callback();
            } else {
                $error = array(
                    'code' => 'access_token_error',
                    'message' => 'Failed to obtain access token',
                    'raw' => array(
                        'response' => $response,
                        'headers' => $headers
                    )
                );

                $this->errorCallback($error);
            }
        } else {
            $error = array(
                'code' => 'oauth2callback_error',
                'raw' => $_GET
            );

            $this->errorCallback($error);
        }
    }
}
