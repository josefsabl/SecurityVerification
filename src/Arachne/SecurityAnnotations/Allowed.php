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
 * @method string|bool|null getResource()
 * @method string|bool|null getPrivilege()
 */
class Allowed extends \Nette\Object implements \Arachne\Verifier\IAnnotation
{

	/** @var string|bool|null */
	protected $resource;

	/** @var string|bool|null */
	protected $privilege;

	/**
	 * @param string|bool|null $resource
	 * @param string|bool|null $privilege
	 */
	public function __construct($resource = \Nette\Security\IAuthorizator::ALL, $privilege = \Nette\Security\IAuthorizator::ALL)
	{
		$this->resource = $resource;
		$this->privilege = $privilege;
	}

	public function getHandlerClass()
	{
		return 'Arachne\SecurityAnnotations\SecurityAnnotationHandler';
	}

}
