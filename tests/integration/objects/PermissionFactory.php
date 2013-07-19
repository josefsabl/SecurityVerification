<?php

namespace Tests\Integration;

class PermissionFactory extends \Nette\Object
{

	/**
	 * @return \Nette\Security\Permission
	 */
	public function create()
	{
		$permission = new \Nette\Security\Permission();
		$permission->addRole('redactor');
		$permission->addResource('Article');
		$permission->allow('redactor', 'Article', 'edit');
		return $permission;
	}

}
