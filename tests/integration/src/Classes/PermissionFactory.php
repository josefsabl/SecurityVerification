<?php

namespace Tests\Integration\Classes;

use Nette\DI\Container;
use Nette\Object;
use Nette\Security\Permission;

/**
 * @author Jáchym Toušek
 */
class PermissionFactory extends Object
{

	/** @var Container */
	private $container;

	public function __construct(Container $container)
	{
		$this->container = $container;
	}

	/**
	 * @return Permission
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
