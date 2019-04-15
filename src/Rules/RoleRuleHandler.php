<?php

declare(strict_types=1);

namespace Arachne\SecurityVerification\Rules;

use Arachne\Security\Authentication\FirewallInterface;
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

    public function __construct(callable $firewallResolver)
    {
        $this->firewallResolver = $firewallResolver;
    }

    /**
     * @throws VerificationException
     */
    public function checkRule(RuleInterface $rule, Request $request, ?string $component = null): void
    {
        if (!$rule instanceof Role) {
            throw new InvalidArgumentException(sprintf('Unknown rule "%s" given.', get_class($rule)));
        }

        $name = $rule->firewall ?: Helpers::getTopModuleName($request->getPresenterName());
        $firewall = call_user_func($this->firewallResolver, $name);
        if (!$firewall instanceof FirewallInterface) {
            throw new UnexpectedValueException(sprintf('Could not find firewall named "%s".', $name));
        }

        $identity = $firewall->getIdentity();
        if ($identity === null || !in_array($rule->role, $identity->getRoles(), true)) {
            throw new VerificationException($rule, sprintf('Role "%s" is required for this request.', $rule->role));
        }
    }
}
