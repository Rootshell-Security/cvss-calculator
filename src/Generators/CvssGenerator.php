<?php

declare(strict_types=1);

namespace Rootshell\Cvss\Generators;

use Rootshell\Cvss\Calculators\Cvss30Calculator;
use Rootshell\Cvss\Calculators\Cvss31Calculator;
use Rootshell\Cvss\Exceptions\CvssException;
use Rootshell\Cvss\Parsers\Cvss31Parser;
use Rootshell\Cvss\ValueObjects\CvssObject;
use Rootshell\Cvss\ValueObjects\CvssResults;

class CvssGenerator
{
    private const VALIDATION_REGEX = '/^CVSS:(3.1|3.0)\/AV:[NALP]\/AC:[LH]\/PR:[NLH]\/UI:[NR]\/S:[UC]\/C:[NLH]\/I:[NLH]\/A:[NLH]/';

    private Cvss31Calculator $calculator31;

    private Cvss31Parser $parser;

    private Cvss30Calculator $calculator30;

    public function __construct(
        Cvss30Calculator $calculator30,
        Cvss31Calculator $calculator31,
        Cvss31Parser $parser
    ) {
        $this->calculator31 = $calculator31;
        $this->parser = $parser;
        $this->calculator30 = $calculator30;
    }

    public function generateScores(string $vector): CvssResults
    {
        if (!$this->validateVector($vector)) {
            throw CvssException::invalidVector();
        }

        $cvssObject = $this->parser->parseVector($vector);

        switch ($this->getVectorVersion($vector)) {
            case CvssObject::VERSION_30:
                $cvssObject->baseScore = $this->calculator30->calculateBaseScore($cvssObject);
                $cvssObject->temporalScore = $this->calculator30->calculateTemporalScore($cvssObject);
                $cvssObject->environmentalScore = $this->calculator30->calculateEnvironmentalScore($cvssObject);
                break;

            case CvssObject::VERSION_31:
                $cvssObject->baseScore = $this->calculator31->calculateBaseScore($cvssObject);
                $cvssObject->temporalScore = $this->calculator31->calculateTemporalScore($cvssObject);
                $cvssObject->environmentalScore = $this->calculator31->calculateEnvironmentalScore($cvssObject);
                break;
        }

        return $cvssObject->getResults();
    }

    private function validateVector(string $vector): bool
    {
        return (bool)preg_match(self::VALIDATION_REGEX, $vector);
    }

    private function getVectorVersion(string $vector): string
    {
        return explode(':', explode('/', $vector)[0])[1];
    }
}