<?php

namespace Tests\Integration\Classes;

use Arachne\Security\Authentication\FirewallInterface;
use Arachne\Security\Authorization\AuthorizatorInterface;
use Arachne\Security\Authorization\Permission;
use Arachne\Security\Authorization\PermissionAuthorizator;
use Nette\Object;
use Nette\Security\IIdentity;
use Nette\Security\IResource;

/**
 * @author Jáchym Toušek <enumag@gmail.com>
 */
class AuthorizatorFactory extends Object
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
		$permission->allow(null, 'Article', 'publish', function (IIdentity $identity, IResource $resource) {
			return $identity->getId() === $resource->getOwnerId();
		});

		return new PermissionAuthorizator($firewall, $permission);
	}

}
