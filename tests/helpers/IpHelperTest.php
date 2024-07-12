<?php

namespace yii1tech\web\test\helpers;

use yii1tech\web\helpers\IpHelper;
use yii1tech\web\test\TestCase;

class IpHelperTest extends TestCase
{
    /**
     * @dataProvider getIpVersionProvider
     *
     * @param string $value
     * @param int $expected
     */
    public function testGetIpVersion(string $value, int $expected): void
    {
        $version = IpHelper::getIpVersion($value);
        $this->assertSame($expected, $version);
    }

    public static function getIpVersionProvider(): array
    {
        return [
            ['192.168.0.1', IpHelper::IPV4],
            ['192.168.0.1/24', IpHelper::IPV4], // IPv4 with CIDR
            ['fb01::1', IpHelper::IPV6],
            ['fb01::1/24', IpHelper::IPV6], // IPv6 with CIDR
            ['', IpHelper::IPV4], // Empty string is treated as IPv4
        ];
    }

    /**
     * @dataProvider expandIpv6Provider
     */
    public function testExpandIpv6(string $value, string $expected): void
    {
        $expanded = IpHelper::expandIPv6($value);
        $this->assertSame($expected, $expanded);
    }

    public static function expandIpv6Provider(): array
    {
        return [
            ['fa01::1', 'fa01:0000:0000:0000:0000:0000:0000:0001'],
            ['2001:db0:1:2::7', '2001:0db0:0001:0002:0000:0000:0000:0007'],
        ];
    }

    public function testIpv6ExpandingWithInvalidValue(): void
    {
        try {
            IpHelper::expandIPv6('fa01::1/64');
            $this->assertTrue(true);
        } catch (\Exception $exception) {
            $this->assertStringEndsWith('Unrecognized address fa01::1/64', $exception->getMessage());
        }
    }

    /**
     * @dataProvider ip2binProvider
     *
     * @param string $value
     * @param string $expected
     */
    public function testIp2bin(string $value, string $expected): void
    {
        $result = IpHelper::ip2bin($value);
        $this->assertSame($expected, $result);
    }

    public static function ip2binProvider(): array
    {
        return [
            ['192.168.1.1', '11000000101010000000000100000001'],
            ['', '00000000000000000000000000000000'],
            ['fa01:0000:0000:0000:0000:0000:0000:0001', '11111010000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001'],
            ['fa01::1', '11111010000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001'],
            ['2620:0:2d0:200::7', '00100110001000000000000000000000000000101101000000000010000000000000000000000000000000000000000000000000000000000000000000000111'],
        ];
    }

    /**
     * @dataProvider inRangeProvider
     *
     * @param string $value
     * @param string $range
     * @param bool $expected
     */
    public function testInRange(string $value, string $range, bool $expected): void
    {
        $result = IpHelper::inRange($value, $range);
        $this->assertSame($expected, $result);
    }

    public static function inRangeProvider(): array
    {
        return [
            ['192.168.1.1/24', '192.168.0.0/23', true],
            ['192.168.1.1/24', '192.168.0.0/24', false],
            ['192.168.1.1/24', '0.0.0.0/0', true],
            ['192.168.1.1/32', '192.168.1.1', true],
            ['192.168.1.1/32', '192.168.1.1/32', true],
            ['192.168.1.1', '192.168.1.1/32', true],
            ['fa01::1/128', 'fa01::/64', true],
            ['fa01::1/128', 'fa01::1/128', true],
            ['fa01::1/64', 'fa01::1/128', false],
            ['2620:0:0:0:0:0:0:0', '2620:0:2d0:200::7/32', true],
        ];
    }
}