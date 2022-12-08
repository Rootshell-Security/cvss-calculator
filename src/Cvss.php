<?php

namespace Rootshell\Cvss;

use Rootshell\Cvss\Calculators\Cvss2Calculator;
use Rootshell\Cvss\Calculators\Cvss30Calculator;
use Rootshell\Cvss\Calculators\Cvss31Calculator;
use Rootshell\Cvss\Calculators\CvssCalculator;
use Rootshell\Cvss\Exceptions\CvssException;
use Rootshell\Cvss\Parsers\Cvss2Parser;
use Rootshell\Cvss\Parsers\Cvss31Parser;
use Rootshell\Cvss\ValueObjects\CvssObject;
use Rootshell\Cvss\ValueObjects\CvssResults;

class Cvss
{
    private const V3_VALIDATION_REGEX = '/^CVSS:(3.1|3.0)\/AV:[NALP]\/AC:[LH]\/PR:[NLH]\/UI:[NR]\/S:[UC]\/C:[NLH]\/I:[NLH]\/A:[NLH]/';
    private const V2_VALIDATION_REGEX = '/AV:[LAN]\/AC:[HML]\/Au:[MSN]\/C:[NCP]\/I:[NCP]\/A:[NCP]/';

    public static function generateScores(string $vector): CvssResults
    {
        if (!self::validateVector($vector)) {
            throw CvssException::invalidVector();
        }

        $vectorVersion = self::getVectorVersion($vector);
        $calculator = self::buildCalculator($vectorVersion);

        $cvssObject = self::parseVector($vector, $vectorVersion);
        $cvssObject->baseScore = $calculator->calculateBaseScore($cvssObject);
        $cvssObject->temporalScore = $calculator->calculateTemporalScore($cvssObject);
        $cvssObject->environmentalScore = $calculator->calculateEnvironmentalScore($cvssObject);

        return $cvssObject->getResults();
    }

    private static function parseVector(string $vector, string $version): CvssObject
    {
        return $version === CvssObject::VERSION_2 ? Cvss2Parser::parseVector($vector) : Cvss31Parser::parseVector($vector);
    }

    private static function buildCalculator(string $version): CvssCalculator
    {
        return match ($version) {
            CvssObject::VERSION_2 => new Cvss2Calculator(),
            CvssObject::VERSION_30 => new Cvss30Calculator(),
            CvssObject::VERSION_31 => new Cvss31Calculator(),
            default => throw CvssException::invalidVector(),
        };
    }

    private static function validateVector(string $vector): bool
    {
        return (bool)preg_match(self::V3_VALIDATION_REGEX, $vector) || self::validCvssTwoVector($vector);
    }

    private static function validCvssTwoVector(string $vector): bool
    {
        return (bool)preg_match(self::V2_VALIDATION_REGEX, $vector);
    }

    private static function getVectorVersion(string $vector): string
    {
        if (self::validCvssTwoVector($vector)) {
            return CvssObject::VERSION_2;
        }

        return explode(':', explode('/', $vector)[0])[1];
    }
}