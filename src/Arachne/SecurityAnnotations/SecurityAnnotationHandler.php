<?php

/**
 * This file is part of the Arachne Security Annotations extenstion
 *
 * Copyright (c) Jáchym Toušek (enumag@gmail.com)
 *
 * For the full copyright and license information, please view the file license.md that was distributed with this source code.
 */

namespace Arachne\SecurityAnnotations;

class SecurityAnnotationHandler extends \Nette\Object implements \Arachne\Verifier\IAnnotationHandler
{

	/** @var \Nette\Security\User */
	protected $user;

	/**
	 * @param \Nette\Security\User $user
	 */
	public function __construct(\Nette\Security\User $user)
	{
		$this->user = $user;
	}

	/**
	 * @param \Arachne\Verifier\IAnnotation $annotation
	 * @param \Nette\Application\Request $request
	 * @throws \Arachne\SecurityAnnotations\FailedAuthorizationException
	 * @throws \Arachne\SecurityAnnotations\FailedAuthenticationException
	 */
	public function checkAnnotation(\Arachne\Verifier\IAnnotation $annotation, \Nette\Application\Request $request)
	{
		if ($annotation instanceof Allowed) {
			if (!$this->user->isAllowed($annotation->getResource(), $annotation->getPrivilege())) {
				throw new FailedAuthorizationException('Required privilege \'' . $annotation->getResource() . ' / ' . $annotation->getPrivilege() . '\' is not granted.');
			}
		} elseif ($annotation instanceof InRole) {
			if (!$this->user->isInRole($annotation->getRole())) {
				throw new FailedAuthorizationException('Role \'' . $annotation->getRole() . '\' is required for this request.');
			}
		} elseif ($annotation instanceof LoggedIn) {
			if ($this->user->isLoggedIn() != $annotation->getFlag()) {
				throw new FailedAuthenticationException('User must ' . ($annotation->getFlag() ? '' : 'not ') . 'be logged in for this request.');
			}
		} else {
			throw new InvalidArgumentException('Unknown condition \'' . get_class($annotation) . '\' given.');
		}
	}

}
