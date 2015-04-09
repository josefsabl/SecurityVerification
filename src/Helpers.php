<?php

/**
 * This file is part of the Arachne
 *
 * Copyright (c) Jáchym Toušek (enumag@gmail.com)
 *
 * For the full copyright and license information, please view the file license.md that was distributed with this source code.
 */

namespace Arachne\SecurityVerification;

use Arachne\SecurityVerification\Exception\InvalidArgumentException;

/**
 * @author Jáchym Toušek <enumag@gmail.com>
 * @internal
 */
class Helpers
{

	/**
	 * @param string $presenter
	 * @return string
	 */
	public static function getTopModuleName($presenter)
	{
		$position = strpos($presenter, ':');
		if ($position === false) {
			throw new InvalidArgumentException("Module name could not be detected.");
		}
		return substr($presenter, 0, $position);
	}

	/**
	 * @param string $presenter
	 * @return string
	 */
	public static function getPresenterName($presenter)
	{
		return substr($presenter, strrpos(':' . $presenter, ':'));
	}

}
