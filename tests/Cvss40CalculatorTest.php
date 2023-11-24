<?php

declare(strict_types=1);

namespace Rootshell\Cvss\Test;

use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ReflectionMethod;
use Rootshell\Cvss\Calculators\Cvss40Calculator;
use Rootshell\Cvss\ValueObjects\Cvss23Object;
use Rootshell\Cvss\ValueObjects\Cvss4Object;

class Cvss40CalculatorTest extends TestCase
{

    private Cvss40Calculator $calculator;

    protected function setUp(): void
    {
        parent::setUp();
        $this->calculator = new Cvss40Calculator;
    }


    public function testInvalidCvssObject(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Wrong CVSS object');

        $cvssObject = new Cvss23Object();

        $this->calculator->calculateBaseScore($cvssObject);
    }


    public function testInvalidMicroVector(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Invalid initial value');

        $cvssObject = new Cvss4Object('2','8', '0', '1', '2', '3');

        $this->calculator->calculateBaseScore($cvssObject);
    }
    
    protected static function getMethod($name): ReflectionMethod
    {
        $class = new ReflectionClass(Cvss40Calculator::class);
        $method = $class->getMethod($name);
        $method->setAccessible(true);
        return $method;
    }

}