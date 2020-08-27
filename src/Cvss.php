<?php

namespace Rootshell\Cvss;

use Rootshell\Cvss\Calculators\Cvss30Calculator;
use Rootshell\Cvss\Calculators\Cvss31Calculator;
use Rootshell\Cvss\Exceptions\CvssException;
use Rootshell\Cvss\Parsers\Cvss31Parser;
use Rootshell\Cvss\ValueObjects\CvssObject;
use Rootshell\Cvss\ValueObjects\CvssResults;

class Cvss
{
    private const VALIDATION_REGEX = '/^CVSS:(3.1|3.0)\/AV:[NALP]\/AC:[LH]\/PR:[NLH]\/UI:[NR]\/S:[UC]\/C:[NLH]\/I:[NLH]\/A:[NLH]/';

    public static function generateScores(string $vector): CvssResults
    {
        if (!self::validateVector($vector)) {
            throw CvssException::invalidVector();
        }
        $calculator = self::getVectorVersion($vector) === CvssObject::VERSION_31 ? new Cvss31Calculator() : new Cvss30Calculator();

        $cvssObject = self::parseVector($vector);
        $cvssObject->baseScore = $calculator->calculateBaseScore($cvssObject);
        $cvssObject->temporalScore = $calculator->calculateTemporalScore($cvssObject);
        $cvssObject->environmentalScore = $calculator->calculateEnvironmentalScore($cvssObject);

        return $cvssObject->getResults();
    }

    private static function parseVector(string $vector): CvssObject
    {
        return (new Cvss31Parser)->parseVector($vector);
    }

    private static function validateVector(string $vector): bool
    {
        return (bool)preg_match(self::VALIDATION_REGEX, $vector);
    }

    private static function getVectorVersion(string $vector): string
    {
        return explode(':', explode('/', $vector)[0])[1];
    }
}