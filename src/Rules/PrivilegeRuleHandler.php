<?php

namespace Arachne\SecurityVerification\Rules;

use Arachne\SecurityVerification\Exception\InvalidArgumentException;
use Arachne\SecurityVerification\Exception\UnexpectedValueException;
use Arachne\SecurityVerification\Helpers;
use Arachne\Verifier\Exception\VerificationException;
use Arachne\Verifier\RuleHandlerInterface;
use Arachne\Verifier\RuleInterface;
use Nette\Application\Request;
use Nette\Security\IResource;
use Symfony\Component\PropertyAccess\PropertyAccess;
use Symfony\Component\PropertyAccess\PropertyAccessorInterface;

/**
 * @author Jáchym Toušek <enumag@gmail.com>
 */
class PrivilegeRuleHandler implements RuleHandlerInterface
{
    /**
     * @var callable
     */
    private $authorizatorResolver;

    /**
     * @var PropertyAccessorInterface
     */
    private $propertyAccessor;

    public function __construct(callable $authorizatorResolver, ?PropertyAccessorInterface $propertyAccessor = null)
    {
        $this->authorizatorResolver = $authorizatorResolver;
        $this->propertyAccessor = $propertyAccessor ?: PropertyAccess::createPropertyAccessor();
    }

    /**
     * @param Privilege $rule
     *
     * @throws VerificationException
     */
    public function checkRule(RuleInterface $rule, Request $request, ?string $component = null): void
    {
        if (!$rule instanceof Privilege) {
            throw new InvalidArgumentException(sprintf('Unknown rule "%s" given.', get_class($rule)));
        }

        $name = $rule->authorizator ?: Helpers::getTopModuleName($request->getPresenterName());
        $authorizator = call_user_func($this->authorizatorResolver, $name);
        if (!$authorizator) {
            throw new UnexpectedValueException(sprintf('Could not find authorizator named "%s".', $name));
        }

        $resource = $this->resolveResource($rule->resource, $request, $component);
        if (!$authorizator->isAllowed($resource, $rule->privilege)) {
            $resourceId = $resource instanceof IResource ? $resource->getResourceId() : $resource;
            throw new VerificationException($rule, sprintf('Required privilege "%s / %s" is not granted.', $resourceId, $rule->privilege));
        }
    }

    /**
     * @return string|IResource
     */
    private function resolveResource(string $resource, Request $request, ?string $component)
    {
        if (strncmp($resource, '$', 1) !== 0) {
            return $resource;
        }
        $parameter = substr($resource, 1);
        if ($component !== null) {
            $parameter = $component.'-'.$parameter;
        }

        if ($parameter === 'this') {
            return Helpers::getPresenterName($request->getPresenterName());
        }

        $object = $this->propertyAccessor->getValue((object) $request->getParameters(), $parameter);
        if (!$object instanceof IResource) {
            throw new InvalidArgumentException(sprintf('Resource "%s" is not an instance of Nette\Security\IResource.', $resource));
        }

        return $object;
    }
}
