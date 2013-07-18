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
 * @Target({"ANNOTATION"})
 * @method string getRole()
 * @property-read string $role
 */
class InRole extends \Nette\Object implements \Arachne\Verifier\IAnnotation
{

	/** @var string */
	protected $role;

	/**
	 * @param string $role
	 */
	public function __construct($role)
	{
		$this->role = $role;
	}

	public function getHandlerClass()
	{
		return 'Arachne\SecurityAnnotations\SecurityAnnotationHandler';
	}

}
