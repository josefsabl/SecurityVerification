<?php

declare(strict_types=1);

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
class NoIdentityRuleHandler implements RuleHandlerInterface
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
     * @param NoIdentity $rule
     *
     * @throws VerificationException
     */
    public function checkRule(RuleInterface $rule, Request $request, ?string $component = null): void
    {
        if (!$rule instanceof NoIdentity) {
            throw new InvalidArgumentException(sprintf('Unknown rule "%s" given.', get_class($rule)));
        }

        $name = $rule->firewall ?: Helpers::getTopModuleName($request->getPresenterName());
        $firewall = call_user_func($this->firewallResolver, $name);
        if (!$firewall) {
            throw new UnexpectedValueException(sprintf('Could not find firewall named "%s".', $name));
        }

        if ($firewall->getIdentity()) {
            throw new VerificationException($rule, 'User must not be logged in for this request.');
        }
    }
}
