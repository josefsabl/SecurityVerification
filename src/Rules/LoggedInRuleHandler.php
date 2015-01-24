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
use Arachne\SecurityVerification\Exception\InvalidArgumentException;
use Arachne\SecurityVerification\Helpers;
use Arachne\Verifier\RuleHandlerInterface;
use Arachne\Verifier\RuleInterface;
use Nette\Application\Request;
use Nette\Object;

/**
 * @author Jáchym Toušek <enumag@gmail.com>
 */
class LoggedInRuleHandler extends Object implements RuleHandlerInterface
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
	 * @throws FailedAuthenticationException
	 * @throws FailedNoAuthenticationException
	 */
	public function checkRule(RuleInterface $rule, Request $request, $component = NULL)
	{
		if (!$rule instanceof LoggedIn) {
			throw new InvalidArgumentException('Unknown rule \'' . get_class($rule) . '\' given.');
		}

		$firewall = $rule->firewall ?: Helpers::getTopModuleName($request->getPresenterName());

		if ($this->firewallResolver->resolve($firewall)->isLoggedIn() !== $rule->flag) {
			if ($rule->flag) {
				throw new FailedAuthenticationException('User must be logged in for this request.');
			} else {
				throw new FailedNoAuthenticationException('User must not be logged in for this request.');
			}
		}
	}

}
