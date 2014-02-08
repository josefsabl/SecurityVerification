<?php

/**
 * This file is part of the Arachne
 *
 * Copyright (c) Jáchym Toušek (enumag@gmail.com)
 *
 * For the full copyright and license information, please view the file license.md that was distributed with this source code.
 */

namespace Arachne\SecurityVerification;

use Arachne\SecurityVerification\Exception\FailedAuthenticationException;
use Arachne\SecurityVerification\Exception\FailedAuthorizationException;
use Arachne\SecurityVerification\Exception\FailedNoAuthenticationException;
use Arachne\SecurityVerification\Exception\InvalidArgumentException;
use Arachne\Verifier\IRule;
use Arachne\Verifier\IRuleHandler;
use Nette\Application\Request;
use Nette\Object;
use Nette\Security\IResource;
use Nette\Security\User;
use Nette\Utils\Strings;

/**
 * @author Jáchym Toušek
 */
class SecurityVerificationHandler extends Object implements IRuleHandler
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
	 * @param IRule $annotation
	 * @param Request $request
	 * @throws FailedAuthenticationException
	 * @throws FailedAuthorizationException
	 * @throws FailedNoAuthenticationException
	 */
	public function checkRule(IRule $annotation, Request $request, $component = NULL)
	{
		if ($annotation instanceof Allowed) {
			$this->checkAnnotationAllowed($annotation, $request, $component);
		} elseif ($annotation instanceof InRole) {
			$this->checkAnnotationInRole($annotation);
		} elseif ($annotation instanceof LoggedIn) {
			$this->checkAnnotationLoggedIn($annotation);
		} else {
			throw new InvalidArgumentException('Unknown annotation \'' . get_class($annotation) . '\' given.');
		}
	}

	/**
	 * @param string $resource
	 * @param Request $request
	 * @param string $component
	 * @return string|IResource
	 */
	protected function resolveResource($resource, Request $request, $component)
	{
		if (!Strings::startsWith($resource, '$')) {
			return $resource;
		}
		$parameters = $request->getParameters();
		$parameter = substr($resource, 1);
		if ($component !== NULL) {
			$parameter = $component . '-' . $parameter;
		}
		if ($parameter === 'this') {
			$presenter = $request->getPresenterName();
			return substr($presenter, strrpos(':' . $presenter, ':'));
		} elseif (!isset($parameters[$parameter])) {
			throw new InvalidArgumentException("Missing parameter '$resource' in given request.");
		} elseif (!$parameters[$parameter] instanceof IResource) {
			throw new InvalidArgumentException("Parameter '$resource' is not an instance of \Nette\Security\IResource.");
		} else {
			return $parameters[$parameter];
		}
	}

	/**
	 * @param Allowed $annotation
	 * @param Request $request
	 * @throws FailedAuthorizationException
	 */
	protected function checkAnnotationAllowed(Allowed $annotation, Request $request, $component)
	{
		$resource = $this->resolveResource($annotation->resource, $request, $component);
		if (!$this->user->isAllowed($resource, $annotation->privilege)) {
			if ($resource instanceof IResource) {
				$resource = $resource->getResourceId();
			}
			throw new FailedAuthorizationException("Required privilege '$resource / $annotation->privilege' is not granted.");
		}
	}

	/**
	 * @param InRole $annotation
	 * @throws FailedAuthorizationException
	 */
	protected function checkAnnotationInRole(InRole $annotation)
	{
		if (!$this->user->isInRole($annotation->role)) {
			throw new FailedAuthorizationException("Role '$annotation->role' is required for this request.");
		}
	}

	/**
	 * @param LoggedIn $annotation
	 * @throws FailedAuthenticationException
	 * @throws FailedNoAuthenticationException
	 */
	protected function checkAnnotationLoggedIn(LoggedIn $annotation)
	{
		if ($this->user->isLoggedIn() !== $annotation->flag) {
			if ($annotation->flag) {
				throw new FailedAuthenticationException('User must be logged in for this request.');
			} else {
				throw new FailedNoAuthenticationException('User must not be logged in for this request.');
			}
		}
	}

}
