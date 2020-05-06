<?php

/*
 * This file is borrowed from StackOverflow bu user http://careers.stackoverflow.com/ircmaxell
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Mokesh;

/**
 * A class to handle secure encryption and decryption of arbitrary data
 *
 * Note that this is not just straight encryption.  It also has a few other
 *  features in it to make the encrypted data far more secure.  Note that any
 *  other implementations used to decrypt data will have to do the same exact
 *  operations.  
 *
 *  @author Anthony Ferrara
 *  @link   http://careers.stackoverflow.com/ircmaxell
 *
 * Security Benefits:
 *
 * - Uses Key stretching
 * - Hides the Initialization Vector
 * - Does HMAC verification of source data
 */
class Encryption 
{

    /**
     * @var string $cipher The mcrypt cipher to use for this instance
     */
    protected $cipher = '';

    /**
     * @var int $mode The mcrypt cipher mode to use
     */
    protected $mode = '';

    /**
     * @var int $rounds The number of rounds to feed into PBKDF2 for key generation
     */
    protected $rounds = 100;

    /**
     * Constructor!
     *
     * @param string $cipher The MCRYPT_* cypher to use for this instance
     * @param int    $mode   The MCRYPT_MODE_* mode to use for this instance
     * @param int    $rounds The number of PBKDF2 rounds to do on the key
     */
    public function __construct($cipher, $mode, $rounds = 100) 
    {
        $this->cipher = $cipher;
        $this->mode = $mode;
        $this->rounds = (int) $rounds;
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

        $data = $this->decode_base64($data);

        $salt = substr($data, 0, 128);
        $enc = substr($data, 128, -64);
        $mac = substr($data, -64);

        list ($cipherKey, $macKey, $iv) = $this->getKeys($salt, $key);

        if (!hash_equals(hash_hmac('sha512', $enc, $macKey, true), $mac)) {
            return false;
        }
        
        $dec = openssl_decrypt($enc, 'AES-256-ECB', $cipherKey, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
        $data = $this->unpad($dec);
        return $data;
    }

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
        $salt = openssl_random_pseudo_bytes(128);
        list ($cipherKey, $macKey, $iv) = $this->getKeys($salt, $key);

        $data = $this->pad($data);

        $enc = openssl_encrypt($data,'AES-256-ECB', $cipherKey, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
        $mac = hash_hmac('sha512', $enc, $macKey, true);
        return $this->encode_base64($salt . $enc . $mac);
    }

    /**
     * Generates a set of keys given a random salt and a master key
     *
     * @param string $salt A random string to change the keys each encryption
     * @param string $key  The supplied key to encrypt with
     *
     * @return array An array of keys (a cipher key, a mac key, and a IV)
     */
    protected function getKeys($salt, $key) 
    {
        //Using CBC mode in calculating cipher IV length just to keep it consistent with previous version, as ECB mode doesn't use IV 
        $ivSize =  openssl_cipher_iv_length('AES-256-CBC');
        
        // hardcoding the key size wrt the CIPHER AES-256-ECB
        $keySize = 32;
        $length = 2 * $keySize + $ivSize;

        $key = $this->pbkdf2('sha512', $key, $salt, $this->rounds, $length);

        $cipherKey = substr($key, 0, $keySize);
        $macKey = substr($key, $keySize, $keySize);
        $iv = substr($key, 2 * $keySize);
        return array($cipherKey, $macKey, $iv);
    }

    /**
     * Stretch the key using the PBKDF2 algorithm
     *
     * @see http://en.wikipedia.org/wiki/PBKDF2
     *
     * @param string $algo   The algorithm to use
     * @param string $key    The key to stretch
     * @param string $salt   A random salt
     * @param int    $rounds The number of rounds to derive
     * @param int    $length The length of the output key
     *
     * @return string The derived key.
     */
    protected function pbkdf2($algo, $key, $salt, $rounds, $length) 
    {
        $size   = strlen(hash($algo, '', true));
        $len    = ceil($length / $size);
        $result = '';
        for ($i = 1; $i <= $len; $i++) {
            $tmp = hash_hmac($algo, $salt . pack('N', $i), $key, true);
            $res = $tmp;
            for ($j = 1; $j < $rounds; $j++) {
                $tmp  = hash_hmac($algo, $tmp, $key, true);
                $res ^= $tmp;
            }
            $result .= $res;
        }
        return substr($result, 0, $length);
    }

    protected function pad($data) 
    {
        //Using CBC mode in calculating cipher IV length just to keep it consistent with previous version, as ECB mode doesn't use IV
        $length = openssl_cipher_iv_length('AES-256-CBC');
        
        $padAmount = $length - strlen($data) % $length;
        if ($padAmount == 0) {
            $padAmount = $length;
        }
        return $data . str_repeat(chr($padAmount), $padAmount);
    }

    protected function unpad($data) 
    {
        //Using CBC mode in calculating cipher IV length just to keep it consistent with previous version, as ECB mode doesn't use IV
        $length = openssl_cipher_iv_length('AES-256-CBC');
        
        $last = ord($data[strlen($data) - 1]);
        if ($last > $length) return false;
        if (substr($data, -1 * $last) !== str_repeat(chr($last), $last)) {
            return false;
        }
        return substr($data, 0, -1 * $last);
    }
    
    public function encode_base64($data) {
        $sBase64 = base64_encode($data);
        return str_replace('=', '', strtr($sBase64, '+/', '-_'));
    }

    public function decode_base64($data) {
        $sBase64 = strtr($data, '-_', '+/');
        return base64_decode($sBase64 . '==');
    }
}

if (function_exists('hash_equals') === false) {
    function hash_equals($a, $b) {
        $key = mcrypt_create_iv(128, MCRYPT_DEV_URANDOM);
        return hash_hmac('sha512', $a, $key) === hash_hmac('sha512', $b, $key);
    }
} 
