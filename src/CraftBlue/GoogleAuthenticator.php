<?php

namespace CraftBlue;

use RandomLib\Factory as RandomFactory;
use SecurityLib\Strength as SecurityStrength;
use Base32\Base32;

/**
 * A Google Authenticator 2Factor authentication implementation written in PHP which Follows RFC6238.
 *
 * This work is derived from the GoogleAuthenticator project written by Michael Kliewe, @PHPGangsta.
 * This new version focuses on industry best practices in security by utilizing third party libraries
 * which specialize in the generation of Base32 strings, cryptographically strong pseudorandom strings,
 * and performing safe string comparisons that aren't prone to timing attacks.
 *
 * @author      Michael Kliewe, Corey Ballou
 * @copyright   2016 POP! Online LLC
 * @license     MIT
 * @link        https://github.com/PHPGangsta/GoogleAuthenticator
 * @link        http://tools.ietf.org/html/rfc6238
 * @link        https://pop.co/
 */
class GoogleAuthenticator
{

    /**
     * The length of the code you wish to have generated for the user to key in.
     * @var int
     */
    protected $_codeLength = 6;

    /**
     * GoogleAuthenticator constructor.
     *
     * @access  public
     * @param   int     $codeLength
     */
    public function __construct($codeLength = 6)
    {
        $this->setCodeLength($codeLength);
    }

    /**
     * Create a new Base32 encoded secret.
     *
     * @param   int     $length     The length of the secret key you wish to generate
     * @return  string
     */
    public function createSecret($length = 16)
    {
        $factory = new RandomFactory();
        $generator = $factory->getGenerator(new SecurityStrength(SecurityStrength::MEDIUM));

        return $generator->generateString($length, $this->getBase32Characters());
    }

    /**
     * Given a secret and a point in time reference, handle calculating the Google Authenticator code based on
     * RFC6238, entitled "TOTP: Time-Based One-Time Password Algorithm."
     *
     * @access  public
     * @param   string      $encodedSecret
     * @param   int|null    $timeSlice                  A timeSlice represents seconds since the Unix epoch divided by 30
     * @link    https://tools.ietf.org/html/rfc6238
     * @return  string
     */
    public function getCode($encodedSecret, $timeSlice = null)
    {
        // if we have no time, generate one ourselves
        if ($timeSlice === null) {
            $timeSlice = floor(time() / 30);
        }

        $secretKey = Base32::decode($encodedSecret);

        // Pack time into binary string
        $time = chr(0) . chr(0) . chr(0) . chr(0) . pack('N*', $timeSlice);
        // Hash it with users secret key
        $hm = hash_hmac('SHA1', $time, $secretKey, true);
        // Use last nipple of result as index/offset
        $offset = ord($this->safeSubstr($hm, -1)) & 0x0F;
        // grab 4 bytes of the result
        $hashpart = $this->safeSubstr($hm, $offset, 4);
        // Unpack binary value
        $value = unpack('N', $hashpart);
        $value = $value[1];
        // Only 32 bits
        $value = $value & 0x7FFFFFFF;
        $modulo = pow(10, $this->_codeLength);

        return str_pad($value % $modulo, $this->_codeLength, '0', STR_PAD_LEFT);
    }

    /**
     * Generate a Google Chart QR code url to be used by the Google Authenticator application for snapping a picture
     * of the QR code. Please note that a label is used to identify which account a key is associated with. It should
     * be unique to a particular user. It contains an account name, which is a URI-encoded string, optionally prefixed
     * by an issuer string identifying the provider or service managing that account. This issuer prefix can be used to
     * prevent collisions between different accounts with different providers that might be identified using the same
     * account name, e.g. the user's email address.
     *
     * To adjust your QR code image, you can optionally pass the following keys in $params:
     *
     *     - height: The width of your QR code image (integer)
     *     - width: The height of your QR code image (integer)
     *     - level: The error correction level allowed by the QR code. Valid values are:
     *       - L: [Default] Allows recovery of up to 7% data loss
     *       - M: Allows recovery of up to 15% data loss
     *       - Q: Allows recovery of up to 25% data loss
     *       - H: Allows recovery of up to 30% data loss
     *
     * @access  public
     * @param   string  $label
     * @param   string  $secret
     * @param   string  $issuer
     * @param   array   $params     User supplied parameters to adjust the output of the QR code
     * @link    https://github.com/google/google-authenticator/wiki/Key-Uri-Format
     * @return  string
     */
    public function getQRCodeUrl($label, $secret, $issuer = null, $params = array())
    {
        $label = $this->validateLabel($label, $issuer);

        $url = 'otpauth://totp/' . $label . '?secret=' . $secret;

        // add the issuer (company namespace)
        if (!empty($issuer) && is_string($issuer)) {
            $url .= '&issuer=' . rawurlencode($issuer);
        }

        $encodedUrl = urlencode($url);

        $width = !empty($params['width']) && (int) $params['width'] > 0 ? (int) $params['width'] : 200;
        $height = !empty($params['height']) && (int) $params['height'] > 0 ? (int) $params['height'] : 200;
        $level = !empty($params['level']) && in_array($params['level'], array('L', 'M', 'Q', 'H')) ? $params['level'] : 'M';

        return 'https://chart.googleapis.com/chart?chs='.$width.'x'.$height.'&chld='.$level.'|0&cht=qr&chl='.$encodedUrl.'';
    }

    /**
     * Check if the client supplied code is correct by comparing it to the Google secret version.
     *
     * Note that any codes generated by Authenticator within the following time period will be accepted:
     * (current_timestamp - ($tolerance * 30 sec)) to (current timestamp + ($tolerance * 30 sec))
     *
     * @access  public
     * @param   string      $secret
     * @param   string      $code
     * @param   int         $tolerance  The +/- time drift allowed when verifying the authenticator code (in 30sec increments)
     * @return  bool
     */
    public function verifyCode($secret, $code, $tolerance = 1)
    {
        $timeSlice = floor(time() / 30);

        for ($i = -$tolerance; $i <= $tolerance; $i++) {
            if ($this->strCompare($this->getCode($secret, $timeSlice + $i), $code)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Set the code length to generate for the user.
     *
     * @access  public
     * @param   int     $codeLength
     * @return  GoogleAuthenticator
     */
    public function setCodeLength($codeLength = 6)
    {
        if (!is_integer($codeLength)) {
            throw new Exception('You must set a valid code length.');
        }

        $this->_codeLength = $codeLength;

        return $this;
    }

    /**
     * Validate that the user supplied label for QR code generation is in the proper format.
     *
     * @access  public
     * @param   string  $label
     * @param   string  $issuer
     * @link    https://github.com/google/google-authenticator/wiki/Key-Uri-Format#label
     * @return  string
     * @throws \Exception
     */
    public function validateLabel($label, $issuer)
    {
        $msg =
            'Your label cannot contain more than a single colon separating the issuer from the label, i.e. "issuer:label".' .
            ' Examples of valid labels are "YourCompany:userlogin@yoursite.com" and "BigCoNamespace:JohnDoe".' .
            ' Please read: https://github.com/google/google-authenticator/wiki/Key-Uri-Format#label';

        // it's possible the label doesn't have an issuer
        $hasColon = strpos($label, ':') !== false;
        $hasColonEncoded = strpos($label, '%3A') !== false;
        if (!$hasColon && !$hasColonEncoded) {
            return urlencode($label);
        }

        // if we have an issuer and the label has a colon, we need to verify the label's issuer matches
        $parts = $hasColon ? explode(':', $label) : explode('%3A', $label);
        if (count($parts) != 2) {
            throw new Exception($msg);
        }

        if (!empty($issuer)) {
            if ($parts[0] !== $issuer) {
                throw new Exception($msg);
            }

            return rawurlencode($parts[0]) . ':' . rawurlencode($parts[1]);
        }

        return rawurlencode($label);
    }

    /**
     * A timing safe string equality check thanks to Anthony Ferrera.
     *
     * @access  protected
     * @param   string  $safe   The internal (safe) value to be checked
     * @param   string  $user   The user submitted (unsafe) value
     * @link    http://blog.ircmaxell.com/2014/11/its-all-about-time.html
     * @return  boolean         True if the two strings are identical.
     */
    protected function strCompare($safe, $user)
    {
        if (version_compare(phpversion(), '5.6.0', '>')) {
            return hash_equals($safe, $user);
        }

        $safeLen = $this->safeStrlen($safe);
        $userLen = $this->safeStrlen($user);

        if ($userLen != $safeLen) {
            return false;
        }

        $result = 0;

        for ($i = 0; $i < $userLen; $i++) {
            $result |= (ord($safe[$i]) ^ ord($user[$i]));
        }

        // They are only identical strings if $result is exactly 0...
        return $result === 0;
    }

    /**
     * Return the length of a string, even in the presence of mbstring.func_overload.
     *
     * @access  protected
     * @param   string  $string     The string we're measuring
     * @return  int
     */
    protected function safeStrlen($string)
    {
        if (function_exists('mb_strlen')) {
            return mb_strlen($string, '8bit');
        }

        return strlen($string);
    }

    /**
     * Return a string contained within a string, even in the presence of mbstring.func_overload.
     *
     * @access  protected
     * @param   string      $string     The string we're searching
     * @param   int         $start      What offset should we begin
     * @param   int|null    $length     How long should the substring be? (default: the remainder)
     * @return  string
     */
    protected function safeSubstr($string, $start = 0, $length = null)
    {
        if (function_exists('mb_substr')) {
            return mb_substr($string, $start, $length, '8bit');
        } elseif ($length !== null) {
            return substr($string, $start, $length);
        }

        return substr($string, $start);
    }

    /**
     * Return the set of allowable characters in a base32 string.
     *
     * @access  protected
     * @return  string
     */
    protected function getBase32Characters()
    {
        return 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    }

}