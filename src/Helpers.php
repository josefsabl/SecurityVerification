<?php

declare(strict_types=1);

namespace Arachne\SecurityVerification;

use Arachne\SecurityVerification\Exception\InvalidArgumentException;

/**
 * @author Jáchym Toušek <enumag@gmail.com>
 *
 * @internal
 */
class Helpers
{
    public static function getTopModuleName(string $presenter): string
    {
        $position = strpos($presenter, ':');
        if ($position === false) {
            throw new InvalidArgumentException('Module name could not be detected.');
        }

        return substr($presenter, 0, $position);
    }

    public static function getPresenterName(string $presenter): string
    {
        return substr($presenter, strrpos(':'.$presenter, ':'));
    }
}
