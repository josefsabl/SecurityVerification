<?php

/**
 * This file is part of the Arachne Security Annotations extenstion
 *
 * Copyright (c) Jáchym Toušek (enumag@gmail.com)
 *
 * For the full copyright and license information, please view the file license.md that was distributed with this source code.
 */

namespace Arachne\SecurityAnnotations;

use Arachne\Verifier\IAnnotation;
use Nette\Object;

/**
 * @Annotation
 * @Target({"CLASS", "METHOD"})
 */
class LoggedIn extends Object implements IAnnotation
{

	/** @var bool */
	public $flag = TRUE;

}
