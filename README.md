<p align="center">
    <a href="https://github.com/yii1tech" target="_blank">
        <img src="https://avatars.githubusercontent.com/u/134691944" height="100px">
    </a>
    <h1 align="center">The Enhanced Web Components Extension for Yii 1</h1>
    <br>
</p>

This extension provides the enhanced components for the web request processing in Yii1 application.

For license information check the [LICENSE](LICENSE.md)-file.

[![Latest Stable Version](https://img.shields.io/packagist/v/yii1tech/web.svg)](https://packagist.org/packages/yii1tech/web)
[![Total Downloads](https://img.shields.io/packagist/dt/yii1tech/web.svg)](https://packagist.org/packages/yii1tech/web)
[![Build Status](https://github.com/yii1tech/web/workflows/build/badge.svg)](https://github.com/yii1tech/web/actions)


Installation
------------

The preferred way to install this extension is through [composer](http://getcomposer.org/download/).

Either run

```
php composer.phar require --prefer-dist yii1tech/web
```

or add

```json
"yii1tech/web": "*"
```

to the "require" section of your composer.json.


Usage
-----

This extension provides the enhanced components for the web request processing in Yii1 application.

In particular, it allows correct and secure processing of the "forwarded" HTTP headers, which is crucial
for distributed application with load balancer.

Application configuration example:

```php
<?php

return [
    'components' => [
        'request' => [
            'class' => yii1tech\web\HttpRequest::class,
            'trustedHosts' => [
                '192.168.0.0/24', // trust "forwarded" headers coming from IP addresses in range `192.168.0.0-192.168.0.254`
            ],
        ],
    ],
    // ...
];
```

Usage example:

```php
<?php

var_dump(Yii::app()->request->getRemoteIP()); // returns IP of current HTTP connection, e.g. load balancer, outputs '192.168.0.1'
var_dump(Yii::app()->request->getUserIp()); // returns user IP address, considering "forwarded" headers, outputs '162.55.123.243'
var_dump(Yii::app()->request->getUserHostAddress()); // alias of `getUserIp()`
```
