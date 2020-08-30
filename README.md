# rootshell/cvss-calculator

[![Source Code][badge-source]][source]
[![Latest Version][badge-release]][release]
[![Software License][badge-license]][license]
[![PHP Version][badge-php]][php]

rootshell/cvss-calculator is a PHP library for translating a CVSS security vector into its relative score. Current support is for CVSS2, CVSS3 and CVSS3.1.

This project adheres to a [Contributor Code of Conduct][conduct]. By
participating in this project and its community, you are expected to uphold this
code.

## Installation

The preferred method of installation is via [Composer][]. Run the following
command to install the package and add it as a requirement to your project's
`composer.json`:

```bash
composer require rootshell/cvss-calculator
```

## Usage

The Cvss calculator can be called statically and pass a CVSS string. A CvssResult Object will be returned with the three result types. 

If the vector is invalid A CvssException will be thrown. 

```php
use Rootshell\Cvss\Cvss;
use Rootshell\Cvss\Exceptions\CvssException;

try {
$result = Cvss::generateScores('CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H');
} catch (CvssException $e) {
    return 'Error!';
}

echo $result->baseScore; // 8.0
echo $result->temporalScore; // 8.0
echo $result->environmentalScore; // 8.0
```




## Copyright and License

The rootshell/cvss-calculator library is copyright © [Rootshell Security LTD](https://www.rootshellsecurity.net/) and
licensed for use under the MIT License (MIT). Please see [LICENSE][] for more
information.

[source]: https://github.com/Rootshell-Security/cvss-calculator
[release]: https://packagist.org/packages/rootshell/cvss-calculator
[php]: https://php.net
[composer]: http://getcomposer.org/
[conduct]: https://github.com/Rootshell-Security/cvss-calculator/blob/master/.github/CODE_OF_CONDUCT.md
[license]: https://github.com/Rootshell-Security/cvss-calculator/blob/master/LICENSE