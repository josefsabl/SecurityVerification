<?php

namespace Tests\Integration\Arachne\Verifier;

final class SecurityAnnotationHandlerTest extends BaseTest
{

	/** @var \Nette\Security\User */
	private $user;

	/** @var \Arachne\Verifier\Verifier */
	private $verifier;

	public function _before()
	{
		parent::_before();
		$this->user = $this->guy->grabService('Nette\Security\User');
		$this->verifier = $this->guy->grabService('Arachne\Verifier\Verifier');
	}

	public function testActionEdit()
	{
		$this->user->login('admin', 'password');

		$request = new \Nette\Application\Request('Article', 'GET', [
			\Nette\Application\UI\Presenter::ACTION_KEY => 'edit',
		]);

		$this->assertTrue($this->verifier->isLinkAvailable($request));
	}

	public function testActionDelete()
	{
		$this->user->login('admin', 'password');

		$request = new \Nette\Application\Request('Article', 'GET', [
			\Nette\Application\UI\Presenter::ACTION_KEY => 'delete',
		]);

		$this->assertFalse($this->verifier->isLinkAvailable($request));
	}

}
