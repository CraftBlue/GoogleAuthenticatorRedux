<?php

use POPdotco\GoogleAuthenticator;

class GoogleAuthenticatorTest extends PHPUnit_Framework_TestCase {

    /**
     * @var GoogleAuthenticator
     */
    protected $ga;

    /**
     * PHPUnit setup.
     */
    protected function setUp()
    {
        $this->ga = new GoogleAuthenticator();
    }

    /**
     *
     */
    public function testItCanBeInstantiated()
    {
        $ga = new GoogleAuthenticator();
        $this->assertInstanceOf('POPdotco\GoogleAuthenticator', $ga);
    }

    /**
     * Ensure that our default secret is 16 characters long.
     */
    public function testCreateSecretDefaultsToSixteenCharacters()
    {
        $secret = $this->ga->createSecret();
        $this->assertEquals(strlen($secret), 16);
    }

    /**
     * Ensure that the user can create a secret of varying lengths from 0 to 100.
     */
    public function testCreateSecretLengthCanBeCustomized()
    {
        for ($secretLength = 10; $secretLength < 100; $secretLength++) {
            $secret = $this->ga->createSecret($secretLength);
            $this->assertEquals(strlen($secret), $secretLength);
        }
    }

    /**
     * Ensure that the generated QR code URL is as expected.
     */
    public function testgetQRCodeGoogleUrlReturnsCorrectUrl()
    {
        $secret = 'SECRET';
        $name   = 'Test';
        $url    = $this->ga->getQRCodeUrl($name, $secret);

        $urlParts = parse_url($url);
        parse_str($urlParts['query'], $queryStringArray);

        $this->assertEquals($urlParts['scheme'], 'https');
        $this->assertEquals($urlParts['host'], 'chart.googleapis.com');
        $this->assertEquals($urlParts['path'], '/chart');

        $expectedChl = 'otpauth://totp/' . $name . '?secret=' . $secret;

        $this->assertEquals($queryStringArray['chl'], $expectedChl);
    }

    /**
     * Test that we properly verify both a valid and invalid code when using the current timestamp.
     */
    public function testVerifyCode()
    {
        $secret = 'SECRET';
        $code   = $this->ga->getCode($secret);
        $result = $this->ga->verifyCode($secret, $code);

        $this->assertEquals(true, $result);

        $code   = 'INVALIDCODE';
        $result = $this->ga->verifyCode($secret, $code);

        $this->assertEquals(false, $result);
    }

    /**
     * Ensure that we can adjust the length of the code and still have the instance returned.
     */
    public function testSetCodeLength()
    {
        $result = $this->ga->setCodeLength(6);

        $this->assertInstanceOf('POPdotco\GoogleAuthenticator', $result);
    }

    /**
     * Validate that a code generated with a specific secret and time slice matches the anticipated output.
     *
     * @param           string          $secret     The secret value used to hash the code
     * @param           int             $timeSlice  The timestamp passed at the time of the code creation
     * @param           string          $code       The resulting code that should be generated
     * @dataProvider    codeProvider
     */
    public function testGetCodeReturnsCorrectValues($secret, $timeSlice, $code)
    {
        $generatedCode = $this->ga->getCode($secret, $timeSlice);

        $this->assertEquals($code, $generatedCode);
    }

    public function testSomeShit()
    {
        $secret = $this->ga->createSecret();

        $code = $this->ga->getCode($secret);
        $result = $this->ga->verifyCode($secret, $code, 1);

        echo print_r($result, true);
    }

    /**
     * A provider of codes to verify for correctness.
     *
     * @return array
     */
    public function codeProvider()
    {
        return array(
            // secret, time, code
            array('SECRET', 0, '200470'),
            array('SECRET', 1385909245, '780018'),
            array('SECRET', 1378934578, '705013'),
        );
    }

} 