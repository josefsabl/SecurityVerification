<?php

namespace Tests\Integration\Classes;

use Arachne\Security\Authentication\FirewallInterface;
use Arachne\Security\Authorization\AuthorizatorInterface;
use Arachne\Security\Authorization\Permission;
use Arachne\Security\Authorization\PermissionAuthorizator;
use Nette\Security\IIdentity;

/**
 * @author Jáchym Toušek <enumag@gmail.com>
 */
class AuthorizatorFactory
{
    /**
     * @return AuthorizatorInterface
     */
    public function create(FirewallInterface $firewall)
    {
        $permission = new Permission();
        $permission->addRole('redactor');
        $permission->addResource('Article');
        $permission->allow('redactor', 'Article', 'edit');
        $permission->allow(
            null,
            'Article',
            'publish',
            function (IIdentity $identity, ArticleEntity $resource) {
                return $identity->getId() === $resource->getOwnerId();
            }
        );

        return new PermissionAuthorizator($firewall, $permission);
    }
}
