<?php

/**
 * This file is part of the Arachne
 *
 * Copyright (c) Jáchym Toušek (enumag@gmail.com)
 *
 * For the full copyright and license information, please view the file license.md that was distributed with this source code.
 */

namespace Arachne\SecurityVerification\Exception;

use Nette\Application\ForbiddenRequestException;
use Nette\Security\IResource;

/**
 * @author Jáchym Toušek
 */
class FailedPrivilegeAuthorizationException extends ForbiddenRequestException
{

	/** @var string|IResource */
	private $resource;

	/** @var string */
	private $privilege;

	/**
	 * @return string|IResource
	 */
	public function getResource()
	{
		return $this->resource;
	}

	/**
	 * @param string|IResource $resource
	 */
	public function setResource($resource)
	{
		$this->resource = $resource;
	}

	/**
	 * @return string
	 */
	public function getPrivilege()
	{
		return $this->privilege;
	}

	/**
	 * @param string $privilege
	 */
	public function setPrivilege($privilege)
	{
		$this->privilege = $privilege;
	}

}
