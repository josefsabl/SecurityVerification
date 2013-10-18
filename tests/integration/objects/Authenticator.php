<?php

namespace Tests\Integration;

use Nette\Object;
use Nette\Security\AuthenticationException;
use Nette\Security\IAuthenticator;
use Nette\Security\Identity;
use Nette\Security\IIdentity;

/**
 * @author Jáchym Toušek
 */
class Authenticator extends Object implements IAuthenticator
{

	/**
	 * @param array $credentials
	 * @return IIdentity
	 * @throws AuthenticationException
	 */
	public function authenticate(array $credentials)
	{
		list($user, $password) = $credentials;
		if ($user === 'admin') {
			if ($password === 'password') {
				return new Identity(1, [ 'redactor' ]);
			} else {
				throw new AuthenticationException("Invalid password.", self::INVALID_CREDENTIAL);
			}
		}
		throw new AuthenticationException("User '$user' not found.", self::IDENTITY_NOT_FOUND);
	}

}
