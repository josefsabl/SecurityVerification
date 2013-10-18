<?php

namespace Tests\Integration;

use Arachne\SecurityAnnotations\Allowed;
use Arachne\SecurityAnnotations\InRole;
use Arachne\SecurityAnnotations\LoggedIn;
use Exception;
use Nette\Application\UI\Presenter;

/**
 * @author Jáchym Toušek
 *
 * @LoggedIn
 * @InRole("redactor")
 */
class ArticlePresenter extends Presenter
{

	final public function __construct()
	{
		throw new Exception('This class is there for annotations only.');
	}

	/**
	 * @Allowed(resource = "Article", privilege = "edit")
	 */
	public function actionEdit($id)
	{
	}

	/**
	 * @Allowed(resource = "Article", privilege = "hide")
	 */
	public function actionHide($id)
	{
	}

	/**
	 * @Allowed(resource = "Article", privilege = "hide")
	 * @Allowed(resource = "Article", privilege = "edit")
	 */
	public function actionDelete($id)
	{
	}

	/**
	 * @Allowed(resource = "$article", privilege = "publish")
	 */
	public function actionPublish(Article $article)
	{
	}

}
