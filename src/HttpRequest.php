<?php

namespace yii1tech\web;

use CHttpRequest;

/**
 * @property-read \yii1tech\web\HeaderCollection $headers The header collection.
 *
 * @author Paul Klimov <klimov.paul@gmail.com>
 * @since 1.0
 */
class HttpRequest extends CHttpRequest
{
    /**
     * @var array the configuration for trusted security related headers.
     *
     * An array key is an IPv4 or IPv6 IP address in CIDR notation for matching a client.
     *
     * An array value is a list of headers to trust. These will be matched against
     * {@see $secureHeaders} to determine which headers are allowed to be sent by a specified host.
     * The case of the header names must be the same as specified in {@see $secureHeaders}.
     *
     * For example:
     *
     * ```php
     * [
     *     '192.168.0.1',
     *     '192.168.0.2',
     * ]
     * ```
     *
     * To trust just the `X-Forwarded-For` header from `10.0.0.1`, use:
     *
     * ```
     * [
     *     '10.0.0.1' => ['X-Forwarded-For']
     * ]
     * ```
     *
     * You can specify IP address as '*' to match any host.
     *
     * Default is to trust all headers except those listed in {@see $secureHeaders} from all hosts.
     * Matches are tried in order and searching is stopped when IP matches.
     *
     * @see $secureHeaders
     */
    public $trustedHosts = [];

    /**
     * @var array lists of headers that are, by default, subject to the trusted host configuration.
     * These headers will be filtered unless explicitly allowed in {@see $trustedHosts}.
     * If the list contains the `Forwarded` header, processing will be done according to RFC 7239.
     * The match of header names is case-insensitive.
     *
     * @see https://en.wikipedia.org/wiki/List_of_HTTP_header_fields
     * @see https://datatracker.ietf.org/doc/html/rfc7239
     * @see $trustedHosts
     */
    public $secureHeaders = [
        // Common:
        'X-Forwarded-For',
        'X-Forwarded-Host',
        'X-Forwarded-Proto',
        'X-Forwarded-Port',

        // Microsoft:
        'Front-End-Https',
        'X-Rewrite-Url',

        // ngrok:
        'X-Original-Host',
    ];

    /**
     * @var string[] List of headers where proxies store the real client IP.
     * It's not advisable to put insecure headers here.
     * To use the `Forwarded` header according to RFC 7239, the header must be added to {@see $secureHeaders} list.
     * The match of header names is case-insensitive.
     *
     * @see $trustedHosts
     * @see $secureHeaders
     */
    public $ipHeaders = [
        'X-Forwarded-For', // Common
    ];

    /**
     * @var string[] List of headers where proxies store the real request port.
     * It's not advisable to put insecure headers here.
     * To use the `Forwarded Port`, the header must be added to {@see $secureHeaders} list.
     * The match of header names is case-insensitive.
     *
     * @see $trustedHosts
     * @see $secureHeaders
     */
    public $portHeaders = [
        'X-Forwarded-Port', // Common
    ];
    /**
     * @var array list of headers to check for determining whether the connection is made via HTTPS.
     * The array keys are header names and the array value is a list of header values that indicate a secure connection.
     * The match of header names and values is case-insensitive.
     * It's not advisable to put insecure headers here.
     *
     * @see $trustedHosts
     * @see $secureHeaders
     */
    public $secureProtocolHeaders = [
        'X-Forwarded-Proto' => ['https'], // Common
        'Front-End-Https' => ['on'], // Microsoft
    ];

    /**
     * @var \yii1tech\web\HeaderCollection Collection of request headers.
     */
    private $_headers;

    /**
     * @var array|null manually set REST parameters.
     */
    private $_restParams;

    /**
     * Returns the header collection.
     * The header collection contains incoming HTTP headers.
     *
     * @return \yii1tech\web\HeaderCollection the header collection
     */
    public function getHeaders(): HeaderCollection
    {
        if ($this->_headers === null) {
            $this->_headers = new HeaderCollection();
            if (function_exists('getallheaders')) {
                $headers = getallheaders();
                foreach ($headers as $name => $value) {
                    $this->_headers->add($name, $value);
                }
            } elseif (function_exists('http_get_request_headers')) {
                $headers = http_get_request_headers();
                foreach ($headers as $name => $value) {
                    $this->_headers->add($name, $value);
                }
            } else {
                // ['prefix' => length]
                $headerPrefixes = ['HTTP_' => 5, 'REDIRECT_HTTP_' => 14];

                foreach ($_SERVER as $name => $value) {
                    foreach ($headerPrefixes as $prefix => $length) {
                        if (strncmp($name, $prefix, $length) === 0) {
                            $name = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, $length)))));
                            $this->_headers->add($name, $value);
                            continue 2;
                        }
                    }
                }
            }

            $this->filterHeaders($this->_headers);
        }

        return $this->_headers;
    }

    /**
     * Filters headers according to the {@see $trustedHosts}.
     *
     * @param \yii1tech\web\HeaderCollection $headerCollection
     */
    protected function filterHeaders(HeaderCollection $headerCollection)
    {
        $trustedHeaders = $this->getTrustedHeaders();

        // remove all secure headers unless they are trusted
        foreach ($this->secureHeaders as $secureHeader) {
            if (!in_array($secureHeader, $trustedHeaders)) {
                $headerCollection->remove($secureHeader);
            }
        }
    }

    /**
     * Trusted headers according to the {@see $trustedHosts}.
     *
     * @return string[]
     */
    protected function getTrustedHeaders(): array
    {
        // do not trust any of the {@see $secureHeaders} by default
        $trustedHeaders = [];

        // check if the client is a trusted host
        if (!empty($this->trustedHosts)) {
            $ip = $this->getRemoteIP();
            foreach ($this->trustedHosts as $ipPattern => $headers) {
                if (!is_array($headers)) {
                    $ipPattern = $headers;
                    $headers = $this->secureHeaders;
                }
                if ($this->checkIpMatch($ip, $ipPattern)) {
                    $trustedHeaders = $headers;
                    break;
                }
            }
        }

        return $trustedHeaders;
    }

    /**
     * @param string $ip IP address to compare against the pattern.
     * @param string $pattern pattern to compare IP address with.
     * @return bool whether the given IP matches the pattern.
     */
    protected function checkIpMatch(?string $ip, string $pattern): bool
    {
        if ($ip === null) {
            return false;
        }

        if ($pattern === '*') {
            return true;
        }

        return $ip === $pattern;
    }

    /**
     * Returns the IP on the other end of this connection.
     * This is always the next hop, any headers are ignored.
     *
     * @return string|null remote IP address, `null` if not available.
     */
    public function getRemoteIP()
    {
        return isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : null;
    }

    /**
     * {@inheritDoc}
     */
    public function getUserHostAddress()
    {
        foreach ($this->ipHeaders as $header) {
            if (($ip = $this->getHeaders()->get($header)) !== null) {
                return $ip;
            }
        }

        return $this->getRemoteIP();
    }

    /**
     * {@inheritDoc}
     */
    public function getServerPort()
    {
        foreach ($this->portHeaders as $portHeader) {
            if (($port = $this->getHeaders()->get($portHeader)) !== null) {
                return (int) $port;
            }
        }

        return isset($_SERVER['SERVER_PORT']) ? (int) $_SERVER['SERVER_PORT'] : null;
    }

    /**
     * {@inheritDoc}
     */
    public function getIsSecureConnection()
    {
        if (isset($_SERVER['HTTPS']) && (strcasecmp($_SERVER['HTTPS'], 'on') === 0 || $_SERVER['HTTPS'] == 1)) {
            return true;
        }

        if (($forwardedHeader = $this->getHeaders()->get('Forwarded')) !== null) {
            if (stripos($forwardedHeader, 'proto=https') !== false) {
                return true;
            }
        }

        foreach ($this->secureProtocolHeaders as $header => $values) {
            if (($headerValue = $this->getHeaders()->get($header)) !== null) {
                foreach ($values as $value) {
                    if (strcasecmp($headerValue, $value) === 0) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Setups (mocks) REST parameters.
     *
     * @param array|null $restParams REST parameters.
     * @return static self reference.
     */
    public function setRestParams($restParams): self
    {
        $this->_restParams = $restParams;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getRestParams()
    {
        if (null !== $this->_restParams) {
            return $this->_restParams;
        }

        return parent::getRestParams();
    }
}