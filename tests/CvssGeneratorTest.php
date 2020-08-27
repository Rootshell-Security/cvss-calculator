<?php

declare(strict_types=1);

namespace Rootshell\Cvss\Test;

use PHPUnit\Framework\TestCase;
use Rootshell\Cvss\Calculators\Cvss30Calculator;
use Rootshell\Cvss\Calculators\Cvss31Calculator;
use Rootshell\Cvss\Exceptions\CvssException;
use Rootshell\Cvss\Generators\CvssGenerator;
use Rootshell\Cvss\Parsers\Cvss31Parser;

class CvssGeneratorTest extends TestCase
{
    private CvssGenerator $cvssGenerator;

    protected function setUp(): void
    {
        parent::setUp();
        $this->cvssGenerator = new CvssGenerator(new Cvss30Calculator, new Cvss31Calculator, new Cvss31Parser);
    }

    /**
     * @dataProvider vectorProvider
     */
    public function testGenerateScores(string $vector, float $baseScore, float $temporalScore, float $environmentScore): void
    {
        $result = $this->cvssGenerator->generateScores($vector);

        self::assertEquals($baseScore, $result->baseScore);
        self::assertEquals($temporalScore, $result->temporalScore);
        self::assertEquals($environmentScore, $result->environmentalScore);
    }

    public function vectorProvider(): array
    {
        return [
            ['CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 8.0, 8.0, 8.0],
            ['CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N/RL:U', 0.0, 0.0, 0.0],
            ['CVSS:3.1/AV:P/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:H/E:H/RL:U/RC:U', 5.0, 4.6, 4.6],
            ['CVSS:3.1/AV:P/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:N', 5.6, 5.6, 5.6],
            ['CVSS:3.1/AV:P/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:N/E:P', 5.6, 5.3, 5.3],
            ['CVSS:3.1/AV:P/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:N/E:P/RL:O', 5.6, 5.1, 5.1],
            ['CVSS:3.1/AV:P/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:N/E:P/RL:O/RC:U', 5.6, 4.7, 4.7],
            ['CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N/E:P/RL:T/RC:R/CR:L/IR:L/AR:L/MAV:L/MAC:L/MPR:H/MUI:R/MS:U/MC:H/MI:H/MA:H', 0.0, 0.0, 4.1],
            ['CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:O/RC:R/CR:M/IR:L/AR:H/MAV:P/MAC:H/MPR:L/MUI:R/MS:U/MC:L/MI:H/MA:H', 5.5, 4.6, 5.2],
            ['CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/CR:M/IR:M/AR:M/MAV:A/MAC:H/MUI:R/MS:U/MC:L/MI:L/MA:L', 8.0, 8.0, 4.3],
            ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:T/RC:U/CR:L/IR:L/AR:H/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:L/MI:H/MA:H', 10.0, 8.1, 5.6],
            ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:T/RC:U/CR:L/IR:L/AR:H/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H', 10.0, 8.1, 5.6],

            ['CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 8.0, 8.0, 8.0],
            ['CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/CR:M/IR:M/AR:M/MAV:A/MAC:H/MUI:R/MS:U/MC:L/MI:L/MA:L', 8.0, 8.0, 4.3],
            ['CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/CR:M/IR:M/AR:M/MAV:A/MAC:H/MUI:R/MS:U/MC:L/MI:L/MA:L', 8.0, 8.0, 4.3],
            ['CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:T/RC:U/CR:L/IR:L/AR:H/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:L/MI:H/MA:H', 10.0, 8.1, 5.6],
            ['CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:T/RC:U/CR:L/IR:L/AR:H/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H', 10.0, 8.1, 5.5],
        ];
    }

    /**
     * @dataProvider invalidVectorProvider
     */
    public function testInvalidVectors(string $vector): void
    {
        $this->expectException(CvssException::class);

        $this->cvssGenerator->generateScores($vector);
    }

    public function invalidVectorProvider(): array
    {
        return [
            ['CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/'],
            ['CVSS:3/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N'],
            ['CVSS:2/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N'],
            ['CVSS:1/AV:P/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:N'],
        ];
    }
}
