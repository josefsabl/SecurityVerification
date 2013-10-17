<?php

/**
 * This file is part of the Arachne Security Annotations extenstion
 *
 * Copyright (c) Jáchym Toušek (enumag@gmail.com)
 *
 * For the full copyright and license information, please view the file license.md that was distributed with this source code.
 */

namespace Arachne\SecurityAnnotations;

use Arachne\SecurityAnnotations\Allowed;
use Arachne\SecurityAnnotations\FailedAuthenticationException;
use Arachne\SecurityAnnotations\FailedAuthorizationException;
use Arachne\SecurityAnnotations\FailedNoAuthenticationException;
use Arachne\SecurityAnnotations\InRole;
use Arachne\SecurityAnnotations\LoggedIn;
use Arachne\Verifier\IAnnotation;
use Arachne\Verifier\IAnnotationHandler;
use Nette\Application\Request;
use Nette\Object;
use Nette\Security\IResource;
use Nette\Security\User;
use Nette\Utils\Strings;

class SecurityAnnotationHandler extends Object implements IAnnotationHandler
{

	/** @var User */
	protected $user;

	/**
	 * @param User $user
	 */
	public function __construct(User $user)
	{
		$this->user = $user;
	}

	/**
	 * @param IAnnotation $annotation
	 * @param Request $request
	 * @throws FailedAuthenticationException
	 * @throws FailedAuthorizationException
	 * @throws FailedNoAuthenticationException
	 */
	public function checkAnnotation(IAnnotation $annotation, Request $request)
	{
		if ($annotation instanceof Allowed) {
			if (!$this->user->isAllowed($annotation->resource, $annotation->privilege)) {
				throw new FailedAuthorizationException('Required privilege \'' . $annotation->resource . ' / ' . $annotation->privilege . '\' is not granted.');
			}
		} elseif ($annotation instanceof InRole) {
			if (!$this->user->isInRole($annotation->role)) {
				throw new FailedAuthorizationException('Role \'' . $annotation->role . '\' is required for this request.');
			}
		} elseif ($annotation instanceof LoggedIn) {
			if ($this->user->isLoggedIn() !== $annotation->flag) {
				if ($annotation->flag) {
					throw new FailedAuthenticationException('User must be logged in for this request.');
				} else {
					throw new FailedNoAuthenticationException('User must not be logged in for this request.');
				}
			}
		} else {
			throw new InvalidArgumentException('Unknown condition \'' . get_class($annotation) . '\' given.');
		}
	}

}
