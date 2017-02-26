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
class RoleRuleHandler implements RuleHandlerInterface
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
     * @param Role    $rule
     * @param Request $request
     * @param string  $component
     *
     * @throws VerificationException
     */
    public function checkRule(RuleInterface $rule, Request $request, $component = null)
    {
        if (!$rule instanceof Role) {
            throw new InvalidArgumentException('Unknown rule \''.get_class($rule).'\' given.');
        }

        $name = $rule->firewall ?: Helpers::getTopModuleName($request->getPresenterName());
        $firewall = call_user_func($this->firewallResolver, $name);
        if (!$firewall) {
            throw new UnexpectedValueException("Could not find firewall named '$name'.");
        }

        if (!in_array($rule->role, $firewall->getIdentity()->getRoles(), true)) {
            throw new VerificationException($rule, "Role '$rule->role' is required for this request.");
        }
    }
}
