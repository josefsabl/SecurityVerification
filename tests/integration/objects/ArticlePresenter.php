<?php

namespace Tests\Integration;

use Arachne\Verifier\Requirements;
use Arachne\SecurityAnnotations\LoggedIn;
use Arachne\SecurityAnnotations\InRole;
use Arachne\SecurityAnnotations\Allowed;

/**
 * @Requirements({
 *   @LoggedIn,
 *   @InRole("redactor"),
 * })
 */
class ArticlePresenter extends \Nette\Application\UI\Presenter
{

	final public function __construct()
	{
		throw new \Exception('This class is there for annotations only.');
	}

	/**
	 * @Requirements({
	 *   @Allowed(resource = "Article", privilege = "edit"),
	 * })
	 */
	public function actionEdit($id)
	{
	}

	/**
	 * @Requirements({
	 *   @Allowed(resource = "Article", privilege = "delete"),
	 * })
	 */
	public function actionDelete($id)
	{
	}

}
