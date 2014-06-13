<?php

namespace Tests\Integration;

use Arachne\Verifier\Verifier;
use Codeception\TestCase\Test;
use Nette\Application\Request;
use Nette\Application\UI\Presenter;
use Nette\Security\User;
use Tests\Integration\Classes\ArticleEntity;
use Tests\Integration\Classes\ArticlePresenter;

/**
 * @author Jáchym Toušek
 */
class SecurityVerificationHandlerTest extends Test
{

	/** @var User */
	private $user;

	/** @var Verifier */
	private $verifier;

	public function _before()
	{
		parent::_before();
		$this->user = $this->guy->grabService(User::class);
		$this->verifier = $this->guy->grabService(Verifier::class);
	}

	public function testActionEdit()
	{
		$this->user->login('admin', 'password');

		$request = new Request('Article', 'GET', [
			Presenter::ACTION_KEY => 'edit',
		]);

		$this->assertTrue($this->verifier->isLinkVerified($request, new ArticlePresenter()));
	}

	public function testActionHide()
	{
		$this->user->login('admin', 'password');

		$request = new Request('Article', 'GET', [
			Presenter::ACTION_KEY => 'hide',
		]);

		$this->assertFalse($this->verifier->isLinkVerified($request, new ArticlePresenter()));
	}

	/**
	 * This test requires all annotations of the same type to be checked, not just the last one.
	 * It will fail if Doctrine\Common\Annotations\IndexedReader is used.
	 */
	public function testActionDelete()
	{
		$this->user->login('admin', 'password');

		$request = new Request('Article', 'GET', [
			Presenter::ACTION_KEY => 'delete',
		]);

		$this->assertFalse($this->verifier->isLinkVerified($request, new ArticlePresenter()));
	}

	public function testActionPublishAllowed()
	{
		$this->user->login('admin', 'password');

		$request = new Request('Article', 'GET', [
			Presenter::ACTION_KEY => 'publish',
			'article' => new ArticleEntity(1),
		]);

		$this->assertTrue($this->verifier->isLinkVerified($request, new ArticlePresenter()));
	}

	public function testActionPublishDisallowed()
	{
		$this->user->login('admin', 'password');

		$request = new Request('Article', 'GET', [
			Presenter::ACTION_KEY => 'publish',
			'article' => new ArticleEntity(2),
		]);

		$this->assertFalse($this->verifier->isLinkVerified($request, new ArticlePresenter()));
	}

}
