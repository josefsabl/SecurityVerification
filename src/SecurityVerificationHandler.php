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
use Arachne\SecurityVerification\Exception\FailedNoAuthenticationException;
use Arachne\SecurityVerification\Exception\FailedPrivilegeAuthorizationException;
use Arachne\SecurityVerification\Exception\FailedRoleAuthorizationException;
use Arachne\SecurityVerification\Exception\InvalidArgumentException;
use Arachne\Verifier\IRule;
use Arachne\Verifier\IRuleHandler;
use Nette\Application\Request;
use Nette\Object;
use Nette\Security\IResource;
use Nette\Security\User;
use Symfony\Component\PropertyAccess\PropertyAccess;
use Symfony\Component\PropertyAccess\PropertyAccessorInterface;

/**
 * @author Jáchym Toušek
 */
class SecurityVerificationHandler extends Object implements IRuleHandler
{

	/** @var User */
	protected $user;

	/** @var PropertyAccessorInterface */
	protected $propertyAccessor;

	/**
	 * @param User $user
	 */
	public function __construct(User $user, PropertyAccessorInterface $propertyAccessor = NULL)
	{
		$this->user = $user;
		$this->propertyAccessor = $propertyAccessor ?: PropertyAccess::createPropertyAccessor();
	}

	/**
	 * @param IRule $rule
	 * @param Request $request
	 * @param string $component
	 * @throws FailedAuthenticationException
	 * @throws FailedNoAuthenticationException
	 * @throws FailedPrivilegeAuthorizationException
	 * @throws FailedRoleAuthorizationException
	 */
	public function checkRule(IRule $rule, Request $request, $component = NULL)
	{
		if ($rule instanceof Allowed) {
			$this->checkRuleAllowed($rule, $request, $component);
		} elseif ($rule instanceof InRole) {
			$this->checkRuleInRole($rule);
		} elseif ($rule instanceof LoggedIn) {
			$this->checkRuleLoggedIn($rule);
		} else {
			throw new InvalidArgumentException('Unknown rule \'' . get_class($rule) . '\' given.');
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
		if (strncmp($resource, '$', 1) !== 0) {
			return $resource;
		}
		$parameter = substr($resource, 1);
		if ($component !== NULL) {
			$parameter = $component . '-' . $parameter;
		}
		if ($parameter === 'this') {
			$presenter = $request->getPresenterName();
			return substr($presenter, strrpos(':' . $presenter, ':'));
		}
		$object = $this->propertyAccessor->getValue((object) $request->getParameters(), $parameter);
		if (!$object instanceof IResource) {
			throw new InvalidArgumentException("Resource '$resource' is not an instance of Nette\Security\IResource.");
		}
		return $object;
	}

	/**
	 * @param Allowed $rule
	 * @param Request $request
	 * @param string $component
	 * @throws FailedPrivilegeAuthorizationException
	 */
	protected function checkRuleAllowed(Allowed $rule, Request $request, $component)
	{
		$resource = $this->resolveResource($rule->resource, $request, $component);
		if (!$this->user->isAllowed($resource, $rule->privilege)) {
			$resourceId = $resource instanceof IResource ? $resource->getResourceId() : $resource;
			$exception = new FailedPrivilegeAuthorizationException("Required privilege '$resourceId / $rule->privilege' is not granted.");
			$exception->setResource($resource);
			$exception->setPrivilege($rule->privilege);
			throw $exception;
		}
	}

	/**
	 * @param InRole $rule
	 * @throws FailedRoleAuthorizationException
	 */
	protected function checkRuleInRole(InRole $rule)
	{
		if (!$this->user->isInRole($rule->role)) {
			$exception =  new FailedRoleAuthorizationException("Role '$rule->role' is required for this request.");
			$exception->setRole($rule->role);
			throw $exception;
		}
	}

	/**
	 * @param LoggedIn $rule
	 * @throws FailedAuthenticationException
	 * @throws FailedNoAuthenticationException
	 */
	protected function checkRuleLoggedIn(LoggedIn $rule)
	{
		if ($this->user->isLoggedIn() !== $rule->flag) {
			if ($rule->flag) {
				throw new FailedAuthenticationException('User must be logged in for this request.');
			} else {
				throw new FailedNoAuthenticationException('User must not be logged in for this request.');
			}
		}
	}

}
