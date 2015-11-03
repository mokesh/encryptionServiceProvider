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

/**
 * Encryptor Trait
 *
 * @author Mukesh Sharma <cogentmukesh@gmail.com>
 * @since  Mon Nov  2 23:07:37 IST 2015
 * @package Mokesh
 */
trait EncryptionTrait
{
    /**
     * Encrypt the supplied data using the supplied key
     * 
     * @param string $data The data to encrypt
     * @param string $key  The key to encrypt with
     *
     * @return string The encrypted data
     */
    public function encrypt($data, $key) 
    {
        return $this['encryptor']->encrypt($data, $key);
    }
    
    /**
     * Decrypt the data with the provided key
     *
     * @param string $data The encrypted data to decrypt
     * @param string $key  The key to use for decryption
     * 
     * @return string|false The returned string if decryption is successful
     *                           false if it is not
     */
    public function decrypt($data, $key) 
    {
        return $this['encryptor']->decrypt($data, $key);
    }
}
