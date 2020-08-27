<?php

declare(strict_types=1);

namespace Rootshell\Cvss\Test;

use PHPUnit\Framework\TestCase;
use Rootshell\Cvss\Calculators\Cvss31Calculator;
use Rootshell\Cvss\ValueObjects\CvssObject;

class Cvss31CalculatorTest extends TestCase
{
    private Cvss31Calculator $calculator;

    protected function setUp(): void
    {
        parent::setUp();
        $this->calculator = new Cvss31Calculator;
    }

    public function testBaseScoreUnchangedScope(): void
    {
        $cvssObject = new CvssObject;
        $cvssObject->confidentiality = 0.22;
        $cvssObject->integrity = 0.22;
        $cvssObject->availability = 0.22;
        $cvssObject->scope = 'U';
        $cvssObject->attackVector = 0.85;
        $cvssObject->attackComplexity = 0.44;
        $cvssObject->privilegesRequired = 0.62;
        $cvssObject->userInteraction = 0.62;

        $result = $this->calculator->calculateBaseScore($cvssObject);

        $this->assertEquals(4.6, $result);
    }

    public function testBaseScoreChangedScope(): void
    {
        $cvssObject = new CvssObject;
        $cvssObject->confidentiality = 0.22;
        $cvssObject->integrity = 0.22;
        $cvssObject->availability = 0.22;
        $cvssObject->scope = 'C';
        $cvssObject->attackVector = 0.85;
        $cvssObject->attackComplexity = 0.44;
        $cvssObject->privilegesRequired = 0.62;
        $cvssObject->userInteraction = 0.62;

        $result = $this->calculator->calculateBaseScore($cvssObject);

        $this->assertEquals(5.4, $result);
    }

    public function testTemporalScore(): void
    {
        $cvssObject = new CvssObject;
        $cvssObject->baseScore = 4.6;
        $cvssObject->exploitCodeMaturity = 0.91;
        $cvssObject->remediationLevel = 0.95;
        $cvssObject->reportConfidence = 0.96;

        $result = $this->calculator->calculateTemporalScore($cvssObject);

        $this->assertEquals(3.9, $result);
    }

    public function testEnvironmentalScoreUnchangedScope(): void
    {
        $cvssObject = new CvssObject;
        $cvssObject->exploitCodeMaturity = 0.91;
        $cvssObject->remediationLevel = 0.95;
        $cvssObject->reportConfidence = 0.96;
        $cvssObject->confidentialityRequirement = 1;
        $cvssObject->integrityRequirement = 0.5;
        $cvssObject->availabilityRequirement = 1.5;
        $cvssObject->modifiedScope = 'U';
        $cvssObject->modifiedAttackVector = 0.2;
        $cvssObject->modifiedAttackComplexity = 0.44;
        $cvssObject->modifiedPrivilegesRequired = 0.68;
        $cvssObject->modifiedUserInteraction = 0.62;
        $cvssObject->modifiedConfidentiality = 0.22;
        $cvssObject->modifiedIntegrity = 0.56;
        $cvssObject->modifiedAvailability = 0.56;

        $result = $this->calculator->calculateEnvironmentalScore($cvssObject);
        $this->assertEquals(5.2, $result);
    }

    public function testEnvironmentalScoreChangedScope(): void
    {
        $cvssObject = new CvssObject;
        $cvssObject->exploitCodeMaturity = 0.91;
        $cvssObject->remediationLevel = 0.95;
        $cvssObject->reportConfidence = 0.96;
        $cvssObject->confidentialityRequirement = 1;
        $cvssObject->integrityRequirement = 0.5;
        $cvssObject->availabilityRequirement = 1.5;
        $cvssObject->modifiedScope = 'C';
        $cvssObject->modifiedAttackVector = 0.2;
        $cvssObject->modifiedAttackComplexity = 0.44;
        $cvssObject->modifiedPrivilegesRequired = 0.68;
        $cvssObject->modifiedUserInteraction = 0.62;
        $cvssObject->modifiedConfidentiality = 0.22;
        $cvssObject->modifiedIntegrity = 0.56;
        $cvssObject->modifiedAvailability = 0.56;

        $result = $this->calculator->calculateEnvironmentalScore($cvssObject);
        $this->assertEquals(5.9, $result);
    }
}
