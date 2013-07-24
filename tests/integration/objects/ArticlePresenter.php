<?php

namespace Tests\Integration;

use Arachne\SecurityAnnotations\LoggedIn;
use Arachne\SecurityAnnotations\InRole;
use Arachne\SecurityAnnotations\Allowed;

/**
 * @LoggedIn
 * @InRole("redactor")
 */
class ArticlePresenter extends \Nette\Application\UI\Presenter
{

	final public function __construct()
	{
		throw new \Exception('This class is there for annotations only.');
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

}
