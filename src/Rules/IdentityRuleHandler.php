<?php

namespace Arachne\SecurityVerification\Rules;

use Arachne\SecurityVerification\Exception\InvalidArgumentException;
use Arachne\SecurityVerification\Exception\UnexpectedValueException;
use Arachne\SecurityVerification\Helpers;
use Arachne\Verifier\Exception\VerificationException;
use Arachne\Verifier\RuleHandlerInterface;
use Arachne\Verifier\RuleInterface;
use Nette\Application\Request;

/**
 * @author Jáchym Toušek <enumag@gmail.com>
 */
class IdentityRuleHandler implements RuleHandlerInterface
{
    /**
     * @var callable
     */
    private $firewallResolver;

    /**
     * @param callable $firewallResolver
     */
    public function __construct(callable $firewallResolver)
    {
        $this->firewallResolver = $firewallResolver;
    }

    /**
     * @param Identity $rule
     * @param Request  $request
     * @param string   $component
     *
     * @throws VerificationException
     */
    public function checkRule(RuleInterface $rule, Request $request, $component = null)
    {
        if (!$rule instanceof Identity) {
            throw new InvalidArgumentException(sprintf('Unknown rule "%s" given.', get_class($rule)));
        }

        $name = $rule->firewall ?: Helpers::getTopModuleName($request->getPresenterName());
        $firewall = call_user_func($this->firewallResolver, $name);
        if (!$firewall) {
            throw new UnexpectedValueException(sprintf('Could not find firewall named "%s".', $name));
        }

        if (!$firewall->getIdentity()) {
            throw new VerificationException($rule, 'User must be logged in for this request.');
        }
    }
}
