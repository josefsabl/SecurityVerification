<?php

/**
 * This file is part of the Arachne Security Annotations extenstion
 *
 * Copyright (c) Jáchym Toušek (enumag@gmail.com)
 *
 * For the full copyright and license information, please view the file license.md that was distributed with this source code.
 */

namespace Arachne\SecurityAnnotations;

/**
 * @Annotation
 * @Target({"CLASS", "METHOD"})
 */
class LoggedIn extends \Nette\Object implements \Arachne\Verifier\IAnnotation
{

	/** @var bool */
	public $flag = TRUE;

	public function getHandlerClass()
	{
		return 'Arachne\SecurityAnnotations\SecurityAnnotationHandler';
	}

}
