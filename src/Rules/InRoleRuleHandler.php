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
use Arachne\SecurityVerification\Exception\FailedRoleAuthorizationException;
use Arachne\SecurityVerification\Exception\InvalidArgumentException;
use Arachne\SecurityVerification\Helpers;
use Arachne\Verifier\RuleHandlerInterface;
use Arachne\Verifier\RuleInterface;
use Nette\Application\Request;
use Nette\Object;

/**
 * @author Jáchym Toušek <enumag@gmail.com>
 */
class InRoleRuleHandler extends Object implements RuleHandlerInterface
{

	/** @var ResolverInterface */
	private $firewallResolver;

	/**
	 * @param ResolverInterface $firewallResolver
	 */
	public function __construct(ResolverInterface $firewallResolver)
	{
		$this->firewallResolver = $firewallResolver;
	}

	/**
	 * @param RuleInterface $rule
	 * @param Request $request
	 * @param string $component
	 * @throws FailedRoleAuthorizationException
	 */
	public function checkRule(RuleInterface $rule, Request $request, $component = NULL)
	{
		if ($rule instanceof InRole) {
			$this->checkRuleInRole($rule, $request);
		} else {
			throw new InvalidArgumentException('Unknown rule \'' . get_class($rule) . '\' given.');
		}
	}

	/**
	 * @param InRole $rule
	 * @throws FailedRoleAuthorizationException
	 */
	private function checkRuleInRole(InRole $rule, Request $request)
	{
		$firewall = $rule->firewall ?: Helpers::getTopModuleName($request->getPresenterName());

		if (!$this->firewallResolver->resolve($firewall)->isInRole($rule->role)) {
			$exception = new FailedRoleAuthorizationException("Role '$rule->role' is required for this request.");
			$exception->setRole($rule->role);
			throw $exception;
		}
	}

}
