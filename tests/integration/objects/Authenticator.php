<?php

namespace Tests\Integration;

class Authenticator extends \Nette\Object implements \Nette\Security\IAuthenticator
{

	/**
	 * @param array $credentials
	 * @return \Nette\Security\IIdentity
	 * @throws \Nette\Security\AuthenticationException
	 */
	public function authenticate(array $credentials)
	{
		list($user, $password) = $credentials;
		if ($user === 'admin') {
			if ($password === 'password') {
				return new \Nette\Security\Identity(1, [ 'redactor' ]);
			} else {
				throw new \Nette\Security\AuthenticationException("Invalid password.", self::INVALID_CREDENTIAL);
			}
		}
		throw new \Nette\Security\AuthenticationException("User '$user' not found.", self::IDENTITY_NOT_FOUND);
	}

}
