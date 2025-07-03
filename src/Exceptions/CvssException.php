<?php

declare(strict_types=1);

namespace Rootshell\Cvss\Exceptions;

use Exception;

final class CvssException extends Exception
{
    public static function invalidValue(): self
    {
        return new self('Value could not be parsed', 403);
    }

    public static function missingValue(): self
    {
        return new self('Missing value', 403);
    }
    public static function invalidVector(): self
    {
        return new self('The vector you have provided is invalid', 403);
    }
}
