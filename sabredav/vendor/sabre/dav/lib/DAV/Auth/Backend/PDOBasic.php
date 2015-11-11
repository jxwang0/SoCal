<?php

namespace Sabre\DAV\Auth\Backend;

/**
 * This is an authentication backend that uses a database to manage passwords.
 *
 * @author Erik Portillo
 */
class PDOBasic extends AbstractBasic {
    /**
     * Authentication Realm.
     *
     * The realm is often displayed by browser clients when showing the
     * authentication dialog.
     *
     * @var string
     */
    protected $realm = 'SabreDAV';

    /**
     * Reference to PDO connection
     *
     * @var PDO
     */
    protected $pdo;

    /**
     * PDO table name we'll be using
     *
     * @var string
     */
    public $tableName = 'users';


    /**
     * Creates the backend object.
     *
     * If the filename argument is passed in, it will parse out the specified file fist.
     *
     * @param PDO $pdo
     */
    function __construct(\PDO $pdo) {

        $this->pdo = $pdo;

    }

    /**
     * Sets the authentication realm for this backend.
     *
     * Be aware that the realm influences the digest hash. Choose the realm
     * wisely, because if you change it later, all the
     * existing hashes will break and nobody can authenticate.
     *
     * @param string $realm
     * @return void
     */
    function setRealm($realm) {

        $this->realm = $realm;

    }

    /**
     * Validates a username and password
     *
     * This method should return true or false depending on if login
     * succeeded.
     *
     * @param string $username
     * @param string $password
     * @return bool
     */
    protected function validateUserPass($username, $password) {

        $stmt = $this->pdo->prepare('SELECT digesta1 FROM ' . $this->tableName . ' WHERE username = ?');
        $stmt->execute([$username]);
        $validHash =  $stmt->fetchColumn() ?: null;

	if ($validHash === false || is_null($validHash)) {
		return false;
	}

	$hash = md5("{$username}:{$this->realm}:{$password}");
	return $hash == $validHash;
    }

}
