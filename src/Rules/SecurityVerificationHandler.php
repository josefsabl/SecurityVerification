<?php

/**
 * This file is part of the Arachne
 *
 * Copyright (c) Jáchym Toušek (enumag@gmail.com)
 *
 * For the full copyright and license information, please view the file license.md that was distributed with this source code.
 */

namespace Arachne\SecurityVerification\Rules;

use Arachne\DIHelpers\ResolverInterface;
use Arachne\SecurityVerification\Exception\FailedAuthenticationException;
use Arachne\SecurityVerification\Exception\FailedNoAuthenticationException;
use Arachne\SecurityVerification\Exception\FailedPrivilegeAuthorizationException;
use Arachne\SecurityVerification\Exception\FailedRoleAuthorizationException;
use Arachne\SecurityVerification\Exception\InvalidArgumentException;
use Arachne\Verifier\RuleHandlerInterface;
use Arachne\Verifier\RuleInterface;
use Nette\Application\Request;
use Nette\Object;
use Nette\Security\IResource;
use Symfony\Component\PropertyAccess\PropertyAccess;
use Symfony\Component\PropertyAccess\PropertyAccessorInterface;

/**
 * @author Jáchym Toušek <enumag@gmail.com>
 */
class SecurityVerificationHandler extends Object implements RuleHandlerInterface
{

	/** @var ResolverInterface */
	private $firewallResolver;

	/** @var ResolverInterface */
	private $authorizatorResolver;

	/** @var PropertyAccessorInterface */
	private $propertyAccessor;

	/**
	 * @param ResolverInterface $firewallResolver
	 * @param ResolverInterface $authorizatorResolver
	 * @param PropertyAccessorInterface $propertyAccessor
	 */
	public function __construct(ResolverInterface $firewallResolver, ResolverInterface $authorizatorResolver, PropertyAccessorInterface $propertyAccessor = NULL)
	{
		$this->firewallResolver = $firewallResolver;
		$this->authorizatorResolver = $authorizatorResolver;
		$this->propertyAccessor = $propertyAccessor ?: PropertyAccess::createPropertyAccessor();
	}

	/**
	 * @param RuleInterface $rule
	 * @param Request $request
	 * @param string $component
	 * @throws FailedAuthenticationException
	 * @throws FailedNoAuthenticationException
	 * @throws FailedPrivilegeAuthorizationException
	 * @throws FailedRoleAuthorizationException
	 */
	public function checkRule(RuleInterface $rule, Request $request, $component = NULL)
	{
		if ($rule instanceof Allowed) {
			$this->checkRuleAllowed($rule, $request, $component);
		} elseif ($rule instanceof InRole) {
			$this->checkRuleInRole($rule, $request);
		} elseif ($rule instanceof LoggedIn) {
			$this->checkRuleLoggedIn($rule, $request);
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
	private function resolveResource($resource, Request $request, $component)
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

	private function resolveName($name, Request $request)
	{
		if ($name) {
			return $name;
		}
		// if name is not specified, return the top-level module name instead
		$presenter = $request->getPresenterName();
		$position = strpos($presenter, ':');
		if ($position === FALSE) {
			throw new \Exception();
		}
		return substr($presenter, 0, $position);
	}

	/**
	 * @param Allowed $rule
	 * @param Request $request
	 * @param string $component
	 * @throws FailedPrivilegeAuthorizationException
	 */
	private function checkRuleAllowed(Allowed $rule, Request $request, $component)
	{
		$resource = $this->resolveResource($rule->resource, $request, $component);
		$authorizator = $this->resolveName($rule->authorizator, $request);
		$allowed = $this->authorizatorResolver->resolve($authorizator)->isAllowed($resource, $rule->privilege);

		if (!$allowed) {
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
	private function checkRuleInRole(InRole $rule, Request $request)
	{
		$firewall = $this->resolveName($rule->firewall, $request);
		$inRole = $this->firewallResolver->resolve($firewall)->isInRole($rule->role);

		if (!$inRole) {
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
	private function checkRuleLoggedIn(LoggedIn $rule, Request $request)
	{
		$firewall = $this->resolveName($rule->firewall, $request);
		$loggedIn = $this->firewallResolver->resolve($firewall)->isLoggedIn();

		if ($loggedIn !== $rule->flag) {
			if ($rule->flag) {
				throw new FailedAuthenticationException('User must be logged in for this request.');
			} else {
				throw new FailedNoAuthenticationException('User must not be logged in for this request.');
			}
		}
	}

}
