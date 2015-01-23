<?php

namespace Tests\Integration\Classes;

use Arachne\Security\AuthorizatorInterface;
use Arachne\Security\FirewallInterface;
use Arachne\Security\Permission;
use Arachne\Security\PermissionAuthorizator;
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
		$permission->allow(NULL, 'Article', 'publish', function (IIdentity $identity, IResource $resource) {
			return $identity->getId() === $resource->getOwnerId();
		});

		return new PermissionAuthorizator($firewall, $permission);
	}

}
