<?php

namespace yii1tech\web\test;

use yii1tech\web\HttpRequest;

class HttpRequestTest extends TestCase
{
    public function testSetupRestParams(): void
    {
        $request = new HttpRequest();

        $restParams = [
            'name' => 'test',
        ];
        $request->setRestParams($restParams);
        $this->assertSame($restParams, $request->getRestParams());
    }

    public function testGetRestParams(): void
    {
        $request = $this->getMockBuilder(HttpRequest::class)
            ->onlyMethods(['getRawBody'])
            ->getMock();

        $restParams = [
            'name' => 'test',
        ];

        $request->method('getRawBody')->willReturn(http_build_query($restParams));

        $this->assertSame($restParams, $request->getRestParams());
    }

    public static function isSecureServerDataProvider(): array
    {
        return [
            [['HTTPS' => 1], true],
            [['HTTPS' => 'on'], true],
            [['HTTPS' => 0], false],
            [['HTTPS' => 'off'], false],
            [[], false],
            [['HTTP_X_FORWARDED_PROTO' => 'https'], false],
            [['HTTP_X_FORWARDED_PROTO' => 'http'], false],
            [[
                'HTTP_X_FORWARDED_PROTO' => 'https',
                'REMOTE_HOST' => 'test.com',
            ], false],
            [[
                'HTTP_X_FORWARDED_PROTO' => 'https',
                'REMOTE_HOST' => 'othertest.com',
            ], false],
            [[
                'HTTP_X_FORWARDED_PROTO' => 'https',
                'REMOTE_ADDR' => '192.168.0.1',
            ], true],
            [[
                'HTTP_X_FORWARDED_PROTO' => 'https',
                'REMOTE_ADDR' => '192.169.0.1',
            ], false],
            [['HTTP_FRONT_END_HTTPS' => 'on'], false],
            [['HTTP_FRONT_END_HTTPS' => 'off'], false],
            [[
                'HTTP_FRONT_END_HTTPS' => 'on',
                'REMOTE_HOST' => 'test.com',
            ], false],
            [[
                'HTTP_FRONT_END_HTTPS' => 'on',
                'REMOTE_HOST' => 'othertest.com',
            ], false],
            [[
                'HTTP_FRONT_END_HTTPS' => 'on',
                'REMOTE_ADDR' => '192.168.0.1',
            ], true],
            [[
                'HTTP_FRONT_END_HTTPS' => 'on',
                'REMOTE_ADDR' => '192.169.0.1',
            ], false],
            // RFC 7239 forwarded from untrusted proxy
            [[
                'HTTP_FORWARDED' => 'proto=https',
            ], false],
            // RFC 7239 forwarded from two untrusted proxies
            [[
                'HTTP_FORWARDED' => 'proto=https,proto=http',
            ], false],
            // RFC 7239 forwarded from trusted proxy
            [[
                'HTTP_FORWARDED' => 'proto=https',
                'REMOTE_ADDR' => '192.168.0.1',
            ], true],
            // RFC 7239 forwarded from trusted proxy, second proxy not encrypted
            [[
                'HTTP_FORWARDED' => 'proto=https,proto=http',
                'REMOTE_ADDR' => '192.168.0.1',
            ], false],
            // RFC 7239 forwarded from trusted proxy, second proxy encrypted, while client request not encrypted
            [[
                'HTTP_FORWARDED' => 'proto=http,proto=https',
                'REMOTE_ADDR' => '192.168.0.1',
            ], true],
            // RFC 7239 forwarded from untrusted proxy
            [[
                'HTTP_FORWARDED' => 'proto=https',
                'REMOTE_ADDR' => '192.169.0.1',
            ], false],
            // RFC 7239 forwarded from untrusted proxy, second proxy not encrypted
            [[
                'HTTP_FORWARDED' => 'proto=https,proto=http',
                'REMOTE_ADDR' => '192.169.0.1',
            ], false],
            // RFC 7239 forwarded from untrusted proxy, second proxy encrypted, while client request not encrypted
            [[
                'HTTP_FORWARDED' => 'proto=http,proto=https',
                'REMOTE_ADDR' => '192.169.0.1',
            ], false],
        ];
    }

    /**
     * @dataProvider isSecureServerDataProvider
     * @param array $server
     * @param bool $expected
     */
    public function testGetIsSecureConnection($server, $expected): void
    {
        $original = $_SERVER;
        $_SERVER = $server;

        $request = new HttpRequest();
        $request->trustedHosts = [
                '192.168.0.1',
            ];
        $request->secureHeaders = [
                'Front-End-Https',
                'X-Rewrite-Url',
                'X-Forwarded-For',
                'X-Forwarded-Host',
                'X-Forwarded-Proto',
                'forwarded',
            ];
        $this->assertEquals($expected, $request->getIsSecureConnection());

        $request = new HttpRequest();
        $request->trustedHosts = [
                '192.168.0.1' => ['Front-End-Https', 'X-Forwarded-Proto', 'forwarded'],
            ];
        $request->secureHeaders = [
                'Front-End-Https',
                'X-Rewrite-Url',
                'X-Forwarded-For',
                'X-Forwarded-Host',
                'X-Forwarded-Proto',
                'forwarded',
            ];

        $this->assertEquals($expected, $request->getIsSecureConnection());

        $_SERVER = $original;
    }
}