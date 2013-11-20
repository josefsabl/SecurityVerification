# Documentation

This extension is here to provide easy annotation-based authorization of presenter actions and signals.


## Installation

The best way to install Arachne/SecurityAnnotations is using [Composer](http://getcomposer.org/):

```sh
$ composer require arachne/security-annotations
```

Now you need to register Arachne/SecurityAnnotations, Arachne/Verifier and Kdyby/Annotations extensions using your [neon](http://ne-on.org/) config file.

```yml
extensions:
	kdyby.annotations: Kdyby\Annotations\DI\AnnotationsExtension
	arachne.verifier: Arachne\Verifier\DI\VerifierExtension
	arachne.securityAnnotations: Arachne\SecurityAnnotations\DI\SecurityAnnotationsExtension
```

See also the documentation of [Kdyby/Annotations](https://github.com/Kdyby/Annotations/blob/master/docs/en/index.md) and Arachne/Verifier.

**Important**: It's very important to read and follow the instalation section of Arachne/Verifier documentation. These annotations won't work at all if you skip it.


## Usage

### Presenter

There are three annotations provided by this extension. It internally uses the Nette\Security\User service.

- `@LoggedIn` - Only logged in users.
- `@LoggedIn(FALSE)` - Only anonymous (not logged in) users.
- `@InRole("admin")` - Only users with the role "admin".
- `@Allowed(resource = "article", privilege = "edit")` - Only users with the "edit" privilege on the "article" resource.

```php
use Arachne\SecurityAnnotations\LoggedIn;
use Arachne\SecurityAnnotations\Allowed;
use Arachne\SecurityAnnotations\InRole;

/**
 * @LoggedIn
 */
class ArticlePresenter extends BasePresenter
{

	/**
	 * @Allowed(resource = "article", privilege = "edit"))
	 */
	public function actionEdit($id)
	{
		// Only users with the "edit" privilege on the "article" resource can edit articles.
	}

	/**
	 * @InRole("redactor")
	 * @InRole("admin")
	 */
	public function actionDelete($id)
	{
		// Only users with both roles "redactor" and "admin" can delete articles.
	}

	public function renderDetail($id)
	{
		// Only logged in users can read articles because of the @LoggedIn annotation used in ArticlePresenter class doc-block.
	}

}
```

If you put some requirement in the presenter class doc-block, it applies globally for all actions, views and signals of this presenter. There is no way to later disable it for one particular action.

### Notes

It's recommended to only use the @Allowed annotation if you use resources-based authorizator like Nette\Security\Permission.

Multiple annotations of the same type won't work correctly if Doctrine\Common\Annotations\IndexedReader is used. Be sure your version of Kdyby/Annotations does not use it!
