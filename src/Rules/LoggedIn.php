<?php

/**
 * This file is part of the Arachne
 *
 * Copyright (c) Jáchym Toušek (enumag@gmail.com)
 *
 * For the full copyright and license information, please view the file license.md that was distributed with this source code.
 */

namespace Arachne\SecurityVerification\Rules;

use Arachne\Verifier\RuleInterface;
use Nette\Object;

/**
 * @author Jáchym Toušek <enumag@gmail.com>
 *
 * @Annotation
 * @Target({"CLASS", "METHOD", "ANNOTATION"})
 */
class LoggedIn extends Object implements RuleInterface
{

	/** @var bool */
	public $flag = TRUE;

	/** @var string */
	public $firewall;

}
