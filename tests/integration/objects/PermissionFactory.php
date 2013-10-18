<?php

namespace Tests\Integration;

use Nette\Object;
use Nette\Security\Permission;

class PermissionFactory extends Object
{

	/** @var \Nette\DI\Container */
	private $container;

	public function injectUser(\Nette\DI\Container $container)
	{
		$this->container = $container;
	}

	/**
	 * @return \Nette\Security\Permission
	 */
	public function create()
	{
		$permission = new Permission();
		$permission->addRole('redactor');
		$permission->addResource('Article');
		$permission->allow('redactor', 'Article', 'edit');
		$permission->allow(NULL, 'Article', 'publish', function (Permission $permission) {
			return $this->container->getByType('Nette\Security\User')->getId() === $permission->getQueriedResource()->getOwnerId();
		});
		return $permission;
	}

}
