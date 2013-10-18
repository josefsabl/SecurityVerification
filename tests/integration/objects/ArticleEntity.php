<?php

namespace Tests\Integration;

use Nette\Object;
use Nette\Security\IResource;

class ArticleEntity extends Object implements IResource
{

	private $ownerId;

	public function __construct($ownerId)
	{
		$this->ownerId = $ownerId;
	}

	public function getOwnerId()
	{
		return $this->ownerId;
	}

	public function getResourceId()
	{
		return 'Article';
	}

}
