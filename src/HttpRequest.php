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
     * @var array[]|null
     */
    private $_secureForwardedHeaderParts;

    /**
     * @var array[]|null
     */
    private $_secureForwardedHeaderTrustedParts;

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
     * Returns decoded forwarded header.
     *
     * @return array[]
     */
    protected function getSecureForwardedHeaderParts(): array
    {
        if ($this->_secureForwardedHeaderParts !== null) {
            return $this->_secureForwardedHeaderParts;
        }
        if (count(preg_grep('/^forwarded$/i', $this->secureHeaders)) === 0) {
            return $this->_secureForwardedHeaderParts = [];
        }

        /*
         * First header is always correct, because proxy CAN add headers
         * after last one is found.
         * Keep in mind that it is NOT enforced, therefore we cannot be
         * sure, that this is really a first one.
         *
         * FPM keeps last header sent which is a bug. You need to merge
         * headers together on your web server before letting FPM handle it
         * @see https://bugs.php.net/bug.php?id=78844
         */
        $forwarded = $this->getHeaders()->get('Forwarded', '');
        if ($forwarded === '') {
            return $this->_secureForwardedHeaderParts = [];
        }

        preg_match_all('/(?:[^",]++|"[^"]++")+/', $forwarded, $forwardedElements);

        foreach ($forwardedElements[0] as $forwardedPairs) {
            preg_match_all('/(?P<key>\w+)\s*=\s*(?:(?P<value>[^",;]*[^",;\s])|"(?P<value2>[^"]+)")/', $forwardedPairs, $matches, PREG_SET_ORDER);
            $this->_secureForwardedHeaderParts[] = array_reduce($matches, function ($carry, $item) {
                $value = $item['value'];
                if (isset($item['value2']) && $item['value2'] !== '') {
                    $value = $item['value2'];
                }
                $carry[strtolower($item['key'])] = $value;

                return $carry;
            }, []);
        }

        return $this->_secureForwardedHeaderParts;
    }

    /**
     * Gets first `Forwarded` header value for token
     *
     * @param string $token Header token
     * @return string|null
     */
    protected function getSecureForwardedHeaderTrustedPart($token): ?string
    {
        $token = strtolower($token);

        if ($parts = $this->getSecureForwardedHeaderTrustedParts()) {
            $lastElement = array_pop($parts);
            if ($lastElement && isset($lastElement[$token])) {
                return $lastElement[$token];
            }
        }

        return null;
    }

    /**
     * Gets only trusted `Forwarded` header parts.
     *
     * @return array[]
     */
    protected function getSecureForwardedHeaderTrustedParts(): array
    {
        if ($this->_secureForwardedHeaderTrustedParts !== null) {
            return $this->_secureForwardedHeaderTrustedParts;
        }

        $trustedHosts = [];
        foreach ($this->trustedHosts as $trustedCidr => $trustedCidrOrHeaders) {
            if (!is_array($trustedCidrOrHeaders)) {
                $trustedCidr = $trustedCidrOrHeaders;
            }
            $trustedHosts[] = $trustedCidr;
        }

        $this->_secureForwardedHeaderTrustedParts = array_filter(
            $this->getSecureForwardedHeaderParts(),
            function ($headerPart) use ($trustedHosts) {
                if (!isset($headerPart['for'])) {
                    return true;
                }

                foreach ($trustedHosts as $trustedHost) {
                    if (!$this->checkIpMatch($headerPart['for'], $trustedHost)) {
                        return true;
                    }
                }

                return false;
            }
        );

        return $this->_secureForwardedHeaderTrustedParts;
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
     * @param string|null $ip IP address to be validated.
     * @return bool weather given IP is in valid format.
     */
    protected function validateIpFormat(?string $ip): bool
    {
        if ($ip === null) {
            return false;
        }

        // IP v4
        if (preg_match('/^(?:(?:2(?:[0-4]\d|5[0-5])|[0-1]?\d?\d)\.){3}(?:(?:2([0-4]\d|5[0-5])|[0-1]?\d?\d))$/', $ip)) {
            return true;
        }

        // IP v6
        if (preg_match('/^(([\da-fA-F]{1,4}:){7}[\da-fA-F]{1,4}|([\da-fA-F]{1,4}:){1,7}:|([\da-fA-F]{1,4}:){1,6}:[\da-fA-F]{1,4}|([\da-fA-F]{1,4}:){1,5}(:[\da-fA-F]{1,4}){1,2}|([\da-fA-F]{1,4}:){1,4}(:[\da-fA-F]{1,4}){1,3}|([\da-fA-F]{1,4}:){1,3}(:[\da-fA-F]{1,4}){1,4}|([\da-fA-F]{1,4}:){1,2}(:[\da-fA-F]{1,4}){1,5}|[\da-fA-F]{1,4}:((:[\da-fA-F]{1,4}){1,6})|:((:[\da-fA-F]{1,4}){1,7}|:)|fe80:(:[\da-fA-F]{0,4}){0,4}%[\da-zA-Z]+|::(ffff(:0{1,4})?:)?((25[0-5]|(2[0-4]|1?\d)?\d)\.){3}(25[0-5]|(2[0-4]|1?\d)?\d)|([\da-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1?[\d])?\d)\.){3}(25[0-5]|(2[0-4]|1?\d)?\d))$/', $ip)) {
            return true;
        }

        return false;
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
     * Returns the user IP address.
     * The IP is determined using headers and / or `$_SERVER` variables.
     *
     * @return string|null user IP address, null if not available
     */
    public function getUserIp()
    {
        $ip = $this->getSecureForwardedHeaderTrustedPart('for');
        if (
            $ip !== null && preg_match(
                '/^\[?(?P<ip>(?:(?:(?:[0-9a-f]{1,4}:){1,6}(?:[0-9a-f]{1,4})?(?:(?::[0-9a-f]{1,4}){1,6}))|(?:\d{1,3}\.){3}\d{1,3}))\]?(?::(?P<port>\d+))?$/',
                $ip,
                $matches
            )
        ) {
            $ip = $this->getUserIpFromIpHeader($matches['ip']);
            if ($ip !== null) {
                return $ip;
            }
        }

        foreach ($this->ipHeaders as $header) {
            if (($ipHeader = $this->getHeaders()->get($header)) !== null) {
                $ip = $this->getUserIpFromIpHeader($ipHeader);
                if ($ip !== null) {
                    return $ip;
                }
            }
        }

        return $this->getRemoteIP();
    }

    /**
     * Return user IP's from IP header.
     *
     * @param string $ips comma separated IP list
     * @return string|null IP as string. Null is returned if IP can not be determined from header.
     * @see getUserHost()
     * @see $ipHeaders
     * @see getTrustedHeaders()
     */
    protected function getUserIpFromIpHeader($ips)
    {
        $ips = trim($ips);
        if ($ips === '') {
            return null;
        }

        $ips = preg_split('/\s*,\s*/', $ips, -1, PREG_SPLIT_NO_EMPTY);
        krsort($ips);
        $resultIp = null;
        foreach ($ips as $ip) {
            if (!$this->validateIpFormat($ip)) {
                break;
            }
            $resultIp = $ip;
            $isTrusted = false;
            foreach ($this->trustedHosts as $trustedCidr => $trustedCidrOrHeaders) {
                if (!is_array($trustedCidrOrHeaders)) {
                    $trustedCidr = $trustedCidrOrHeaders;
                }
                if ($this->checkIpMatch($ip, $trustedCidr)) {
                    $isTrusted = true;
                    break;
                }
            }
            if (!$isTrusted) {
                break;
            }
        }

        return $resultIp;
    }

    /**
     * {@inheritDoc}
     */
    public function getUserHostAddress()
    {
        return $this->getUserIp();
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

        if (($proto = $this->getSecureForwardedHeaderTrustedPart('proto')) !== null) {
            return strcasecmp($proto, 'https') === 0;
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