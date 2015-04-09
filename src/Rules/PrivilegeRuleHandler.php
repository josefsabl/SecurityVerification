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
use Arachne\SecurityVerification\Exception\InvalidArgumentException;
use Arachne\SecurityVerification\Exception\UnexpectedValueException;
use Arachne\SecurityVerification\Helpers;
use Arachne\Verifier\Exception\VerificationException;
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
class PrivilegeRuleHandler extends Object implements RuleHandlerInterface
{

	/** @var ResolverInterface */
	private $authorizatorResolver;

	/** @var PropertyAccessorInterface */
	private $propertyAccessor;

	/**
	 * @param ResolverInterface $authorizatorResolver
	 * @param PropertyAccessorInterface $propertyAccessor
	 */
	public function __construct(ResolverInterface $authorizatorResolver, PropertyAccessorInterface $propertyAccessor = null)
	{
		$this->authorizatorResolver = $authorizatorResolver;
		$this->propertyAccessor = $propertyAccessor ?: PropertyAccess::createPropertyAccessor();
	}

	/**
	 * @param Privilege $rule
	 * @param Request $request
	 * @param string $component
	 * @throws VerificationException
	 */
	public function checkRule(RuleInterface $rule, Request $request, $component = null)
	{
		if (!$rule instanceof Privilege) {
			throw new InvalidArgumentException('Unknown rule \'' . get_class($rule) . '\' given.');
		}

		$name = $rule->authorizator ?: Helpers::getTopModuleName($request->getPresenterName());
		$authorizator = $this->authorizatorResolver->resolve($name);
		if (!$authorizator) {
			throw new UnexpectedValueException("Could not find authorizator named '$name'.");
		}

		$resource = $this->resolveResource($rule->resource, $request, $component);
		if (!$authorizator->isAllowed($resource, $rule->privilege)) {
			$resourceId = $resource instanceof IResource ? $resource->getResourceId() : $resource;
			throw new VerificationException($rule, "Required privilege '$resourceId / $rule->privilege' is not granted.");
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
		if ($component !== null) {
			$parameter = $component . '-' . $parameter;
		}
		if ($parameter === 'this') {
			return Helpers::getPresenterName($request->getPresenterName());
		}
		$object = $this->propertyAccessor->getValue((object) $request->getParameters(), $parameter);
		if (!$object instanceof IResource) {
			throw new InvalidArgumentException("Resource '$resource' is not an instance of Nette\Security\IResource.");
		}
		return $object;
	}

}
