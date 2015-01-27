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
class Privilege extends Object implements RuleInterface
{

	/** @var string */
	public $resource;

	/** @var string */
	public $privilege;

	/** @var string */
	public $authorizator;

}
