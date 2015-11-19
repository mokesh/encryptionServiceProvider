<?php

/*
 * This file is part of EncryptionServiceProvider package.
 *
 * (c) Mukesh Sharma <cogentmukesh@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Mokesh;

use Silex\Application;
use Silex\ServiceProviderInterface;

/**
 * EncryptionServiceProvider for Silex
 *
 * @author Mukesh Sharma <cogentmukesh@gmail.com>
 * @since  Mon Nov  2 23:07:37 IST 2015
 * @package Mokesh
 */
class EncryptionServiceProvider implements ServiceProviderInterface
{
    const DEFAULT_CRYPT_CIPHER  = MCRYPT_RIJNDAEL_128;
    const DEFAULT_CRYPT_MODE    = MCRYPT_MODE_ECB;


    public function register(Application $app)
    {
        $app['encryptor'] = function () use ($app) {

            // Set the defaults if not yet set
            if (isset($app['encryptor.crypt.cipher']) === false) {
                $app['encryptor.crypt.cipher']  = EncryptionServiceProvider::DEFAULT_CRYPT_CIPHER;
            }
            if (isset($app['encryptor.crypt.mode']) === false) {
                $app['encryptor.crypt.mode']    = EncryptionServiceProvider::DEFAULT_CRYPT_MODE;
            }

            return new Encryption($app['encryptor.crypt.cipher'], $app['encryptor.crypt.mode']);
        };
    }

    public function boot(Application $app)
    {
    }
}
