<?php

namespace Tests\Integration;

use Nette\Object;
use Nette\Security\Permission;

class PermissionFactory extends Object
{

	/**
	 * @return \Nette\Security\Permission
	 */
	public function create()
	{
		$permission = new Permission();
		$permission->addRole('redactor');
		$permission->addResource('Article');
		$permission->allow('redactor', 'Article', 'edit');
		return $permission;
	}

}
