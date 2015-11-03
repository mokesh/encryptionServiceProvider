<?php

/*
 * This file is part of EncryptionServiceProvider Package.
 *
 * (c) Mukesh Sharma <cogentmukesh@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Mokesh;

use Silex\Application;

/**
 * @author Mukesh Sharma <cogentmukesh@gmail.com>
 */
class EncryptionServiceProviderTest extends \PHPUnit_Framework_TestCase
{
    /**
     * Bare minimum test for Encryption/Decryption 
     */
    public function testEncryptionDecryptionWithDefaultSettings()
    {
        $app   = new Application();

        $key   = 'MyHighlySecureKey';
        $data  = 'ConfidentailData';

        $app->register(new EncryptionServiceProvider());

        $encryptedData = $app['encryptor']->encrypt($data, $key);

        $this->assertSame($app['encryptor']->decrypt($encryptedData, $key), $data);
    }
}
