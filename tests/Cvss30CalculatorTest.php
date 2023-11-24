<?php

declare(strict_types=1);

namespace Rootshell\Cvss\Test;

use PHPUnit\Framework\TestCase;
use Rootshell\Cvss\Calculators\Cvss30Calculator;
use Rootshell\Cvss\Calculators\Cvss31Calculator;
use Rootshell\Cvss\ValueObjects\Cvss23Object;
use Rootshell\Cvss\ValueObjects\Cvss4Object;

class Cvss30CalculatorTest  extends TestCase
{

    private Cvss30Calculator $calculator;

    protected function setUp(): void
    {
        parent::setUp();
        $this->calculator = new Cvss30Calculator();
    }

    public function testCalculateModifiedImpactSubScoreInvalidCvssObject(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Wrong CVSS object');

        $cvssObject = new Cvss4Object('','','','','','');
        $this->calculator->calculateModifiedImpactSubScore($cvssObject);
    }

    public function testCalculateModifiedImpact(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Wrong CVSS object');

        $cvssObject = new Cvss4Object('','','','','','');
        $this->calculator->calculateModifiedImpact($cvssObject);
    }
}